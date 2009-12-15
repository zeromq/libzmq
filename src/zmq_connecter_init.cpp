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

#include "zmq_connecter_init.hpp"
#include "zmq_connecter.hpp"
#include "io_thread.hpp"
#include "session.hpp"
#include "err.hpp"

zmq::zmq_connecter_init_t::zmq_connecter_init_t (io_thread_t *parent_,
      socket_base_t *owner_, fd_t fd_, const options_t &options_,
      const char *session_name_, const char *address_) :
    owned_t (parent_, owner_),
    options (options_),
    session_name (session_name_)
{
    //  Create associated engine object.
    engine = new zmq_engine_t (parent_, fd_, options, true, address_);
    zmq_assert (engine);
}

zmq::zmq_connecter_init_t::~zmq_connecter_init_t ()
{
    if (engine)
        delete engine;
}

bool zmq::zmq_connecter_init_t::read (::zmq_msg_t *msg_)
{
    //  Send identity.
    int rc = zmq_msg_init_size (msg_, options.identity.size ());
    zmq_assert (rc == 0);
    memcpy (zmq_msg_data (msg_), options.identity.c_str (),
        options.identity.size ());

    //  Initialisation is done at this point. Disconnect the engine from
    //  the init object.
    engine->unplug ();

    //  Find the session associated with this connecter. If it doesn't exist
    //  drop the newly created connection. If it does, attach it to the
    //  connection.
    session_t *session = NULL;
    if (!session_name.empty ())
        session = owner->find_session (session_name.c_str ());
    if (!session) {

        //  TODO:
        //  The socket is already closing. The session is already shut down,
        //  so no point in continuing with connecting. Shut the connection down.
        zmq_assert (false);
    }

    //  No need to increment seqnum as it was alredy incremented above.
    send_attach (session, engine, false);
    engine = NULL;

    //  Destroy the init object.
    term ();

    return true;
}

bool zmq::zmq_connecter_init_t::write (::zmq_msg_t *msg_)
{
    return false;
}

void zmq::zmq_connecter_init_t::flush ()
{
    //  We are not expecting any messages. No point in flushing.
}

void zmq::zmq_connecter_init_t::detach (owned_t *reconnecter_)
{
    //  Plug in the reconnecter object.
    zmq_assert (reconnecter_);
    send_plug (reconnecter_);
    send_own (owner, reconnecter_);

    //  This function is called by engine when disconnection occurs.
    //  The engine will destroy itself, so we just drop the pointer here and
    //  start termination of the init object.
    engine = NULL;
    term ();
}

zmq::io_thread_t *zmq::zmq_connecter_init_t::get_io_thread ()
{
    return choose_io_thread (options.affinity);
}

class zmq::socket_base_t *zmq::zmq_connecter_init_t::get_owner ()
{
    return owner;
}

const char *zmq::zmq_connecter_init_t::get_session_name ()
{
    return session_name.c_str ();
}

void zmq::zmq_connecter_init_t::process_plug ()
{
    zmq_assert (engine);
    engine->plug (this);
}

void zmq::zmq_connecter_init_t::process_unplug ()
{
    if (engine)
        engine->unplug ();
}
