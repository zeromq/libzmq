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

#include "zmq_init.hpp"
#include "io_thread.hpp"
#include "session.hpp"
#include "err.hpp"

zmq::zmq_init_t::zmq_init_t (io_thread_t *parent_, socket_base_t *owner_,
      fd_t fd_, bool connected_, const options_t &options_) :
    owned_t (parent_, owner_),
    connected (connected_),
    options (options_)
{
    //  Create associated engine object.
    engine = new zmq_engine_t (parent_, fd_);
    zmq_assert (engine);
}

zmq::zmq_init_t::~zmq_init_t ()
{
    if (engine)
        delete engine;
}

bool zmq::zmq_init_t::read (::zmq_msg *msg_)
{
    //  On the listening side, no initialisation data are sent to the peer.
    if (!connected)
        return false;

    //  Send identity.
    int rc = zmq_msg_init_size (msg_, options.identity.size ());
    zmq_assert (rc == 0);
    memcpy (zmq_msg_data (msg_), options.identity.c_str (),
        options.identity.size ());

    //  Initialisation is done.
    create_session ();

    return true;
}

bool zmq::zmq_init_t::write (::zmq_msg *msg_)
{
    //  On the connecting side no initialisation data are expected.
    if (connected)
        return false;

    //  Retreieve the identity.
    options.identity = std::string ((const char*) zmq_msg_data (msg_),
        zmq_msg_size (msg_));

    //  Initialisation is done.
    create_session ();

    return true;
}

void zmq::zmq_init_t::flush ()
{
    //  No need to do anything. zmq_init_t does no batching of messages.
    //  Each message is processed immediately on write.
}

void zmq::zmq_init_t::process_plug ()
{
    zmq_assert (engine);
    engine->plug (this);
    owned_t::process_plug ();
}

void zmq::zmq_init_t::process_unplug ()
{
    if (engine)
        engine->unplug ();
}

void zmq::zmq_init_t::create_session ()
{
    //  Disconnect engine from the init object.
    engine->unplug ();

    //  Create the session instance.
    io_thread_t *io_thread = choose_io_thread (options.affinity);
    session_t *session = new session_t (io_thread, owner, engine);
    zmq_assert (session);
    engine = NULL;

    //  Pass session/engine pair to a chosen I/O thread.
    send_plug (session);
    send_own (owner, session);

    //  Destroy the init object.
    term ();
}
