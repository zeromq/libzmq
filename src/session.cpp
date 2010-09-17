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

zmq::session_t::session_t (class io_thread_t *io_thread_,
      class socket_base_t *socket_, const options_t &options_) :
    own_t (io_thread_),
    options (options_),
    in_pipe (NULL),
    incomplete_in (false),
    active (true),
    out_pipe (NULL),
    engine (NULL),
    socket (socket_),
    io_thread (io_thread_),
    attach_processed (false),
    term_processed (false)
{    
}

zmq::session_t::~session_t ()
{
    zmq_assert (!in_pipe);
    zmq_assert (!out_pipe);

    if (engine)
        engine->terminate ();
}

void zmq::session_t::terminate ()
{
    if (in_pipe)
        in_pipe->terminate ();
    if (out_pipe)
        out_pipe->terminate ();
}

bool zmq::session_t::read (::zmq_msg_t *msg_)
{
    if (!in_pipe || !active)
        return false;

    if (!in_pipe->read (msg_)) {
        active = false;
        return false;
    }

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
    if (inpipe_) {
        zmq_assert (!in_pipe);
        in_pipe = inpipe_;
        active = true;
        in_pipe->set_event_sink (this);
    }

    if (outpipe_) {
        zmq_assert (!out_pipe);
        out_pipe = outpipe_;
        out_pipe->set_event_sink (this);
    }

    attach_processed = true;
    finalise ();
}

void zmq::session_t::terminated (reader_t *pipe_)
{
    active = false;
    in_pipe = NULL;
    finalise ();
}

void zmq::session_t::terminated (writer_t *pipe_)
{
    out_pipe = NULL;
    finalise ();
}

void zmq::session_t::activated (reader_t *pipe_)
{
    zmq_assert (in_pipe == pipe_);
    active = true;
    if (engine)
        engine->activate_out ();
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

void zmq::session_t::finalise ()
{
    //  If all conditions are met, proceed with termination:
    //  1. Owner object already asked us to terminate.
    //  2. The pipes were already attached to the session.
    //  3. Both pipes have already terminated. Note that inbound pipe
    //     is terminated after delimiter is read, i.e. all messages
    //     were already sent to the wire.
    if (term_processed && attach_processed && !in_pipe && !out_pipe)
        own_t::process_term ();
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

    //  Check whether the required pipes already exist. If not so, we'll
    //  create them and bind them to the socket object.
    reader_t *socket_reader = NULL;
    writer_t *socket_writer = NULL;

    if (options.requires_in && !out_pipe) {
        create_pipe (socket, this, options.hwm, options.swap, &socket_reader,
            &out_pipe);
        out_pipe->set_event_sink (this);
    }

    if (options.requires_out && !in_pipe) {
        create_pipe (this, socket, options.hwm, options.swap, &in_pipe,
            &socket_writer);
        in_pipe->set_event_sink (this);
    }

    if (socket_reader || socket_writer)
        send_bind (socket, socket_reader, socket_writer, peer_identity_);

    //  Plug in the engine.
    zmq_assert (!engine);
    zmq_assert (engine_);
    engine = engine_;
    engine->plug (io_thread, this);

    attach_processed = true;

    //  Trigger the notfication about the attachment.
    attached (peer_identity_);
}

void zmq::session_t::detach ()
{
    //  Engine is dead. Let's forget about it.
    engine = NULL;

    detached ();
}

void zmq::session_t::process_term ()
{
    //  Here we are pugging into the own_t's termination mechanism.
    //  The goal is to postpone the termination till all the pending messages
    //  are sent to the peer.
    term_processed = true;
    finalise ();
}

bool zmq::session_t::register_session (const blob_t &name_, session_t *session_)
{
    return socket->register_session (name_, session_);
}

void zmq::session_t::unregister_session (const blob_t &name_)
{
    socket->unregister_session (name_);
}

void zmq::session_t::attached (const blob_t &peer_identity_)
{
}

void zmq::session_t::detached ()
{
}

