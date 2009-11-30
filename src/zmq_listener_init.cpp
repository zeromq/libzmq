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

#include "zmq_listener_init.hpp"
#include "io_thread.hpp"
#include "session.hpp"
#include "err.hpp"

zmq::zmq_listener_init_t::zmq_listener_init_t (io_thread_t *parent_,
      socket_base_t *owner_, fd_t fd_, const options_t &options_) :
    owned_t (parent_, owner_),
    options (options_),
    has_peer_identity (false)
{
    //  Create associated engine object.
    engine = new zmq_engine_t (parent_, fd_);
    zmq_assert (engine);
}

zmq::zmq_listener_init_t::~zmq_listener_init_t ()
{
    if (engine)
        delete engine;
}

bool zmq::zmq_listener_init_t::read (::zmq_msg_t *msg_)
{
    return false;
}

bool zmq::zmq_listener_init_t::write (::zmq_msg_t *msg_)
{
    //  Once we've got peer's identity we aren't interested in subsequent
    //  messages.
    if (has_peer_identity)
        return false;

    //  Retreieve the remote identity. We'll use it as a local session name.
    has_peer_identity = true;
    peer_identity.assign ((const char*) zmq_msg_data (msg_),
        zmq_msg_size (msg_));

    return true;
}

void zmq::zmq_listener_init_t::flush ()
{
    if (!has_peer_identity)
        return;

    //  Initialisation is done. Disconnect the engine from the init object.
    engine->unplug ();

    //  Have a look whether the session already exists. If it does, attach it
    //  to the engine. If it doesn't create it first.
    session_t *session = NULL;
    if (!peer_identity.empty ())
        session = owner->find_session (peer_identity.c_str ());
    if (!session) {
        io_thread_t *io_thread = choose_io_thread (options.affinity);
        session = new session_t (io_thread, owner, peer_identity.c_str (),
            options, false);
        zmq_assert (session);
        send_plug (session);
        send_own (owner, session);

        //  Reserve a sequence number for following 'attach' command.
        session->inc_seqnum ();
    }
    send_attach (session, engine);
    engine = NULL;

    //  Destroy the init object.
    term ();
}

void zmq::zmq_listener_init_t::detach ()
{
    //  This function is called by engine when disconnection occurs.
    //  The engine will destroy itself, so we just drop the pointer here and
    //  start termination of the init object.
    engine = NULL;
    term ();
}

void zmq::zmq_listener_init_t::process_plug ()
{
    zmq_assert (engine);
    engine->plug (this);
    owned_t::process_plug ();
}

void zmq::zmq_listener_init_t::process_unplug ()
{
    if (engine)
        engine->unplug ();
}
