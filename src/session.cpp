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
      zmq_engine_t *engine_) :
    owned_t (parent_, owner_),
    engine (engine_)
{
}

zmq::session_t::~session_t ()
{
}

bool zmq::session_t::read (::zmq_msg *msg_)
{
    return false;
}

bool zmq::session_t::write (::zmq_msg *msg_)
{
    return false;
}

void zmq::session_t::flush ()
{
}

void zmq::session_t::process_plug ()
{
    zmq_assert (engine);
    engine->plug (this);
    owned_t::process_plug ();
}

void zmq::session_t::process_unplug ()
{
    zmq_assert (engine);
    engine->unplug ();
    delete engine;
}
