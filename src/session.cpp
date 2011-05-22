/*
    Copyright (c) 2007-2011 iMatix Corporation
    Copyright (c) 2007-2011 Other contributors as noted in the AUTHORS file

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "session.hpp"
#include "socket_base.hpp"
#include "i_engine.hpp"
#include "err.hpp"
#include "pipe.hpp"
#include "likely.hpp"

zmq::session_t::session_t (class io_thread_t *io_thread_,
      class socket_base_t *socket_, const options_t &options_) :
    own_t (io_thread_, options_),
    io_object_t (io_thread_),
    pipe (NULL),
    incomplete_in (false),
    engine (NULL),
    socket (socket_),
    io_thread (io_thread_),
    pipe_attached (false),
    delimiter_processed (false),
    force_terminate (false),
    has_linger_timer (false),
    state (active)
{    
}

zmq::session_t::~session_t ()
{
    zmq_assert (!pipe);

    if (engine)
        engine->terminate ();
}

void zmq::session_t::proceed_with_term ()
{
    if (state == terminating)
        return;

    zmq_assert (state == pending);
    state = terminating;

    //  If there's still a pending linger timer, remove it.
    if (has_linger_timer) {
        cancel_timer (linger_timer_id);
        has_linger_timer = false;
    }

    if (pipe) {
        register_term_acks (1);
        pipe->terminate ();
    }

    //  The session has already waited for the linger period. We don't want
    //  the child objects to linger any more thus linger is set to zero.
    own_t::process_term (0);
}

bool zmq::session_t::read (msg_t *msg_)
{
    if (!pipe)
        return false;

    if (!pipe->read (msg_))
        return false;

    incomplete_in = msg_->flags () & msg_t::more;
    return true;
}

bool zmq::session_t::write (msg_t *msg_)
{
    if (pipe && pipe->write (msg_)) {
        int rc = msg_->init ();
        errno_assert (rc == 0);
        return true;
    }

    return false;
}

void zmq::session_t::flush ()
{
    if (pipe)
        pipe->flush ();
}

void zmq::session_t::clean_pipes ()
{
    if (pipe) {

        //  Get rid of half-processed messages in the out pipe. Flush any
        //  unflushed messages upstream.
        pipe->rollback ();
        pipe->flush ();

        //  Remove any half-read message from the in pipe.
        while (incomplete_in) {
            msg_t msg;
            int rc = msg.init ();
            errno_assert (rc == 0);
            if (!read (&msg)) {
                zmq_assert (!incomplete_in);
                break;
            }
            rc = msg.close ();
            errno_assert (rc == 0);
        }
    }
}

void zmq::session_t::attach_pipe (pipe_t *pipe_, const blob_t &peer_identity_)
{
    zmq_assert (!pipe_attached);
    pipe_attached = true;
    
    if (pipe_) {
        zmq_assert (!pipe);
        pipe = pipe_;
        pipe->set_event_sink (this);
    }

    //  If we are already terminating, terminate the pipes straight away.
    if (state == terminating) {
        if (pipe) {
            pipe->terminate ();
            register_term_acks (1);
        }
    }
}

void zmq::session_t::terminated (pipe_t *pipe_)
{
    zmq_assert (pipe == pipe_);

    // If we are in process of being closed, but still waiting for all
    // pending messeges being sent, we can terminate here.
    if (state == pending)
        proceed_with_term ();

    pipe = NULL;
    if (state == terminating)
        unregister_term_ack ();
}

void zmq::session_t::read_activated (pipe_t *pipe_)
{
    zmq_assert (pipe == pipe_);

    if (likely (engine != NULL))
        engine->activate_out ();
    else
        pipe->check_read ();
}

void zmq::session_t::write_activated (pipe_t *pipe_)
{
    zmq_assert (pipe == pipe_);

    if (engine)
        engine->activate_in ();
}

void zmq::session_t::process_plug ()
{
}

void zmq::session_t::process_attach (i_engine *engine_,
    const blob_t &peer_identity_)
{
    //  If we are already terminating, we destroy the engine straight away.
    //  Note that we don't have to unplug it before deleting as it's not
    //  yet plugged to the session.
    if (state == terminating) {
        if (engine_)
            delete engine_;
        return;
    }

    //  If some other object (e.g. init) notifies us that the connection failed
    //  without creating an engine we need to start the reconnection process.
    if (!engine_) {
        zmq_assert (!engine);
        detached ();
        return;
    }

    //  Trigger the notfication event about the attachment.
    if (!attached (peer_identity_)) {
        delete engine_;
        return;
    }

    //  Check whether the required pipe already exists and create it
    //  if it does not.
    if (!pipe_attached) {
        zmq_assert (!pipe);
        pipe_attached = true;

        object_t *parents [2] = {this, socket};
        pipe_t *pipes [2] = {NULL, NULL};
        int hwms [2] = {options.rcvhwm, options.sndhwm};
        bool delays [2] = {true, true};
        int rc = pipepair (parents, pipes, hwms, delays);
        errno_assert (rc == 0);

        //  Plug the local end of the pipe.
        pipes [0]->set_event_sink (this);

        //  Remember the local end of the pipe.
        pipe = pipes [0];

        //  Ask socket to plug into the remote end of the pipe.
        send_bind (socket, pipes [1], peer_identity_);
    }

    //  Plug in the engine.
    zmq_assert (!engine);
    engine = engine_;
    engine->plug (io_thread, this);
}

void zmq::session_t::detach ()
{
    //  Engine is dead. Let's forget about it.
    engine = NULL;

    //  Remove any half-done messages from the pipes.
    clean_pipes ();

    //  Send the event to the derived class.
    detached ();

    //  Just in case there's only a delimiter in the inbound pipe.
    if (pipe)
        pipe->check_read ();
}

void zmq::session_t::process_term (int linger_)
{
    zmq_assert (state == active);
    state = pending;

    //  If linger is set to zero, we can terminate the session straight away
    //  not waiting for the pending messages to be sent.
    if (linger_ == 0) {
        proceed_with_term ();
        return;
    }

    //  If there's finite linger value, set up a timer.
    if (linger_ > 0) {
       zmq_assert (!has_linger_timer);
       add_timer (linger_, linger_timer_id);
       has_linger_timer = true;
    }

    //  If there's no engine and there's only delimiter in the pipe it wouldn't
    //  be ever read. Thus we check for it explicitly.
    if (pipe)
        pipe->check_read ();

    //  If there's no in pipe, there are no pending messages to send.
    //  We can proceed with the shutdown straight away. Also, if there is
    //  pipe, but the delimiter was already processed, we can terminate
    //  immediately. Alternatively, if the derived session type have
    //  called 'terminate' we'll finish straight away.
    if (delimiter_processed || force_terminate ||
          (!options.immediate_connect && !pipe))
        proceed_with_term ();
}

void zmq::session_t::timer_event (int id_)
{
    //  Linger period expired. We can proceed with termination even though
    //  there are still pending messages to be sent.
    zmq_assert (id_ == linger_timer_id);
    has_linger_timer = false;
    proceed_with_term ();
}

bool zmq::session_t::has_engine ()
{
    return engine != NULL;
}

bool zmq::session_t::register_session (const blob_t &name_, session_t *session_)
{
    return socket->register_session (name_, session_);
}

void zmq::session_t::unregister_session (const blob_t &name_)
{
    socket->unregister_session (name_);
}

void zmq::session_t::terminate ()
{
    force_terminate = true;
    own_t::terminate ();
}
