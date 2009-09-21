/*
    Copyright (c) 2007-2009 FastMQ Inc.

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

#include "session.hpp"
#include "i_engine.hpp"
#include "err.hpp"
#include "pipe.hpp"

zmq::session_t::session_t (object_t *parent_, socket_base_t *owner_,
      const char *name_, const options_t &options_, bool reconnect_) :
    owned_t (parent_, owner_),
    in_pipe (NULL),
    active (true),
    out_pipe (NULL),
    engine (NULL),
    name (name_),
    options (options_),
    reconnect (reconnect_)
{
}

zmq::session_t::~session_t ()
{
    zmq_assert (!in_pipe);
    zmq_assert (!out_pipe);
}

bool zmq::session_t::read (::zmq_msg_t *msg_)
{
    if (!active)
        return false;

    return in_pipe->read (msg_);
}

bool zmq::session_t::write (::zmq_msg_t *msg_)
{
    if (!out_pipe)
        return true;

    if (out_pipe->write (msg_)) {
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

void zmq::session_t::detach ()
{
    //  TODO:  Start reconnection process here.

    //  Engine is terminating itself. No need to deallocate it from here.
    engine = NULL;

    //  In the case od anonymous connection, terminate the session.
    if (name.empty ())
        term ();
}

void zmq::session_t::attach_pipes (class reader_t *inpipe_,
    class writer_t *outpipe_)
{
    if (inpipe_) {
        zmq_assert (!in_pipe);
        in_pipe = inpipe_;
        active = true;
        in_pipe->set_endpoint (this);
    }

    if (outpipe_) {
        zmq_assert (!out_pipe);
        out_pipe = outpipe_;
        out_pipe->set_endpoint (this);
    }
}

void zmq::session_t::detach_inpipe (reader_t *pipe_)
{
    active = false;
    in_pipe = NULL;
}

void zmq::session_t::detach_outpipe (writer_t *pipe_)
{
    out_pipe = NULL;
}

void zmq::session_t::kill (reader_t *pipe_)
{
    active = false;
}

void zmq::session_t::revive (reader_t *pipe_)
{
    zmq_assert (in_pipe == pipe_);
    active = true;
    if (engine)
        engine->revive ();
}

void zmq::session_t::process_plug ()
{
    //  Register the session with the socket.
    if (!name.empty ()) {
        bool ok = owner->register_session (name.c_str (), this);

        //  There's already a session with the specified identity.
        //  We should syslog it and drop the session. TODO
        zmq_assert (ok);
    }

    //  If session is created by 'connect' function, it has the pipes set
    //  already. Otherwise, it's being created by the listener and the pipes
    //  are yet to be created.
    if (!in_pipe && !out_pipe) {
        pipe_t *inbound = new pipe_t (this, owner, options.hwm, options.lwm);
        zmq_assert (inbound);
        in_pipe = &inbound->reader;
        in_pipe->set_endpoint (this);
        pipe_t *outbound = new pipe_t (owner, this, options.hwm, options.lwm);
        zmq_assert (outbound);
        out_pipe = &outbound->writer;
        out_pipe->set_endpoint (this);
        send_bind (owner, this, &outbound->reader, &inbound->writer);
    }

    owned_t::process_plug ();
}

void zmq::session_t::process_unplug ()
{
    //  Unregister the session from the socket.
    if (!name.empty ()) {
        bool ok = owner->unregister_session (name.c_str ());
        zmq_assert (ok);
    }

    //  Ask associated pipes to terminate.
    if (in_pipe) {
        in_pipe->term ();
        in_pipe = NULL;
    }
    if (out_pipe) {
        out_pipe->term ();
        out_pipe = NULL;
    }

    if (engine) {
        engine->unplug ();
        delete engine;
        engine = NULL;
    }
}

void zmq::session_t::process_attach (i_engine *engine_)
{
    zmq_assert (!engine);
    zmq_assert (engine_);
    engine = engine_;
    engine->plug (this);

    owned_t::process_attach (engine_);
}
