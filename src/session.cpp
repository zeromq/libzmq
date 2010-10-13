/*
    Copyright (c) 2007-2010 iMatix Corporation

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the Lesser GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    Lesser GNU General Public License for more details.

    You should have received a copy of the Lesser GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <new>

#include "session.hpp"
#include "socket_base.hpp"
#include "i_engine.hpp"
#include "err.hpp"
#include "pipe.hpp"
#include "likely.hpp"

zmq::session_t::session_t (class io_thread_t *io_thread_,
      class socket_base_t *socket_, const options_t &options_) :
    own_t (io_thread_),
    options (options_),
    in_pipe (NULL),
    incomplete_in (false),
    out_pipe (NULL),
    engine (NULL),
    socket (socket_),
    io_thread (io_thread_),
    pipes_attached (false),
    delimiter_processed (false),
    force_terminate (false),
    state (active)
{    
}

zmq::session_t::~session_t ()
{
    zmq_assert (!in_pipe);
    zmq_assert (!out_pipe);

    if (engine)
        engine->terminate ();
}

void zmq::session_t::proceed_with_term ()
{
    if (state == terminating)
        return;

    zmq_assert (state == pending);
    state = terminating;

    if (in_pipe) {
        register_term_acks (1);
        in_pipe->terminate ();
    }
    if (out_pipe) {
        register_term_acks (1);
        out_pipe->terminate ();
    }

    own_t::process_term ();
}

bool zmq::session_t::read (::zmq_msg_t *msg_)
{
    if (!in_pipe)
        return false;

    if (!in_pipe->read (msg_))
        return false;

    incomplete_in = msg_->flags & ZMQ_MSG_MORE;
    return true;
}

bool zmq::session_t::write (::zmq_msg_t *msg_)
{
    if (out_pipe && out_pipe->write (msg_)) {
        zmq_msg_init (msg_);
        return true;
    }

    return false;
}

void zmq::session_t::flush ()
{
    if (out_pipe)
        out_pipe->flush ();
}

void zmq::session_t::clean_pipes ()
{
    //  Get rid of half-processed messages in the out pipe. Flush any
    //  unflushed messages upstream.
    if (out_pipe) {
        out_pipe->rollback ();
        out_pipe->flush ();
    }

    //  Remove any half-read message from the in pipe.
    if (in_pipe) {
        while (incomplete_in) {
            zmq_msg_t msg;
            zmq_msg_init (&msg);
            if (!read (&msg)) {
                zmq_assert (!incomplete_in);
                break;
            }
            zmq_msg_close (&msg);
        }
    }
}

void zmq::session_t::attach_pipes (class reader_t *inpipe_,
    class writer_t *outpipe_, const blob_t &peer_identity_)
{
    zmq_assert (!pipes_attached);
    pipes_attached = true;
    
    if (inpipe_) {
        zmq_assert (!in_pipe);
        in_pipe = inpipe_;
        in_pipe->set_event_sink (this);
    }

    if (outpipe_) {
        zmq_assert (!out_pipe);
        out_pipe = outpipe_;
        out_pipe->set_event_sink (this);
    }

    //  If we are already terminating, terminate the pipes straight away.
    if (state == terminating) {
        if (in_pipe) {
            in_pipe->terminate ();
            register_term_acks (1);
        }
        if (out_pipe) {
            out_pipe->terminate ();
            register_term_acks (1);
        }
    }
}

void zmq::session_t::delimited (reader_t *pipe_)
{
    zmq_assert (in_pipe == pipe_);
    zmq_assert (!delimiter_processed);
    delimiter_processed = true;

    //  If we are in process of being closed, but still waiting for all
    //  pending messeges being sent, we can terminate here.
    if (state == pending)
        proceed_with_term ();
}

void zmq::session_t::terminated (reader_t *pipe_)
{
    zmq_assert (in_pipe == pipe_);
    in_pipe = NULL;
    if (state == terminating)
        unregister_term_ack ();
}

void zmq::session_t::terminated (writer_t *pipe_)
{
    zmq_assert (out_pipe == pipe_);
    out_pipe = NULL;
    if (state == terminating)
        unregister_term_ack ();
}

void zmq::session_t::activated (reader_t *pipe_)
{
    zmq_assert (in_pipe == pipe_);

    if (likely (engine != NULL))
        engine->activate_out ();
    else
        in_pipe->check_read ();
}

void zmq::session_t::activated (writer_t *pipe_)
{
    zmq_assert (out_pipe == pipe_);
    if (engine)
        engine->activate_in ();
}

void zmq::session_t::process_plug ()
{
}

void zmq::session_t::process_attach (i_engine *engine_,
    const blob_t &peer_identity_)
{
    //  If some other object (e.g. init) notifies us that the connection failed
    //  we need to start the reconnection process.
    if (!engine_) {
        zmq_assert (!engine);
        detached ();
        return;
    }

    //  If we are already terminating, we destroy the engine straight away.
    if (state == terminating) {
        delete engine;
        return;
    }

    //  Check whether the required pipes already exist. If not so, we'll
    //  create them and bind them to the socket object.
    if (!pipes_attached) {
        zmq_assert (!in_pipe && !out_pipe);
        pipes_attached = true;
        reader_t *socket_reader = NULL;
        writer_t *socket_writer = NULL;

        //  Create the pipes, as required.
        if (options.requires_in) {
            create_pipe (socket, this, options.hwm, options.swap, &socket_reader,
                &out_pipe);
            out_pipe->set_event_sink (this);
        }
        if (options.requires_out) {
            create_pipe (this, socket, options.hwm, options.swap, &in_pipe,
                &socket_writer);
            in_pipe->set_event_sink (this);
        }

        //  Bind the pipes to the socket object.
        if (socket_reader || socket_writer)
            send_bind (socket, socket_reader, socket_writer, peer_identity_);
    }

    //  Plug in the engine.
    zmq_assert (!engine);
    zmq_assert (engine_);
    engine = engine_;
    engine->plug (io_thread, this);

    //  Trigger the notfication about the attachment.
    attached (peer_identity_);
}

void zmq::session_t::detach ()
{
    //  Engine is dead. Let's forget about it.
    engine = NULL;

    //  Remove any half-done messages from the pipes.
    clean_pipes ();

    //  Send the event to the derived class.
    detached ();

    //  Just in case, there's only a delimiter in the inbound pipe.
    if (in_pipe)
        in_pipe->check_read ();
}

void zmq::session_t::process_term ()
{
    zmq_assert (state == active);
    state = pending;

    //  If there's no engine and there's only delimiter in the pipe it wouldn't
    //  be ever read. Thus we check for it explicitly.
    if (in_pipe)
        in_pipe->check_read ();

    //  If there's no in pipe there are no pending messages to send.
    //  We can proceed with the shutdown straight away. Also, if there is
    //  inbound pipe, but the delimiter was already processed, we can
    //  terminate immediately. Alternatively, if the derived session type have
    //  called 'terminate' we'll finish straight away.
    if (!options.requires_out || delimiter_processed || force_terminate ||
        (!options.immediate_connect && !in_pipe))
        proceed_with_term ();
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
