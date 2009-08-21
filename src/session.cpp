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
#include "zmq_engine.hpp"
#include "err.hpp"

zmq::session_t::session_t (object_t *parent_, socket_base_t *owner_,
      const char *name_) :
    owned_t (parent_, owner_),
    engine (NULL),
    name (name_)
{
}

zmq::session_t::~session_t ()
{
}

bool zmq::session_t::read (::zmq_msg_t *msg_)
{
    return false;
}

bool zmq::session_t::write (::zmq_msg_t *msg_)
{
    return false;
}

void zmq::session_t::flush ()
{
}

void zmq::session_t::process_plug ()
{
    //  Register the session with the socket.
    bool ok = owner->register_session (name.c_str (), this);

    //  There's already a session with the specified identity.
    //  We should syslog it and drop the session. TODO
    zmq_assert (ok);

    owned_t::process_plug ();
}

void zmq::session_t::process_unplug ()
{
    //  Unregister the session from the socket.
    bool ok = owner->unregister_session (name.c_str ());
    zmq_assert (ok);

    if (engine) {
        engine->unplug ();
        delete engine;
        engine = NULL;
    }
}

void zmq::session_t::process_attach (class zmq_engine_t *engine_)
{
    zmq_assert (engine_);
    engine = engine_;
    engine->plug (this);

    owned_t::process_attach (engine_);
}
