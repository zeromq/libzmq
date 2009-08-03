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

#include <string>

#include "../include/zmq.h"

#include "session_stub.hpp"
#include "i_engine.hpp"
#include "listener.hpp"
#include "err.hpp"

zmq::session_stub_t::session_stub_t (listener_t *listener_) :
    state (reading_identity),
    engine (NULL),
    listener (listener_),
    index (-1)
{
}

void zmq::session_stub_t::terminate ()
{
    if (engine)
        engine->terminate ();
    delete this;
}

void zmq::session_stub_t::shutdown ()
{
    if (engine)
        engine->shutdown ();
    delete this;
}

zmq::session_stub_t::~session_stub_t ()
{
}

void zmq::session_stub_t::set_engine (i_engine *engine_)
{
    zmq_assert (!engine_ || !engine);
    engine = engine_;
}

bool zmq::session_stub_t::read (struct zmq_msg *msg_)
{
    //  No messages are sent to the connecting peer.
    return false;
}

bool zmq::session_stub_t::write (struct zmq_msg *msg_)
{
    //  The first message arrived is the connection identity.
    if (state == reading_identity) {
        identity = std::string ((const char*) zmq_msg_data (msg_),
            zmq_msg_size (msg_));
        state = has_identity;
        return true;
    }

    //  We are not interested in any subsequent messages.
    return false;
}

void zmq::session_stub_t::flush ()
{
    //  We have the identity. At this point we can find the correct session and
    //  attach it to the connection.
    if (state == has_identity) {

        //  At this point the stub will be deleted. Return immediately without
        //  touching 'this' pointer.
        listener->got_identity (this, identity.c_str ());
        return;
    }
}

zmq::i_engine *zmq::session_stub_t::detach_engine ()
{
    //  Ask engine to unregister from the poller.
    i_engine *e = engine;
    engine->detach ();
    return e;
}

void zmq::session_stub_t::set_index (int index_)
{
    index = index_;
}

int zmq::session_stub_t::get_index ()
{
    return index;
}
