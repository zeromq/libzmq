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

#include <string.h>

#include "zmq_init.hpp"
#include "zmq_engine.hpp"
#include "io_thread.hpp"
#include "session.hpp"
#include "uuid.hpp"
#include "err.hpp"

zmq::zmq_init_t::zmq_init_t (io_thread_t *parent_, socket_base_t *owner_,
      fd_t fd_, const options_t &options_, bool reconnect_,
      const char *protocol_, const char *address_, uint64_t session_ordinal_) :
    owned_t (parent_, owner_),
    sent (false),
    received (false),
    session_ordinal (session_ordinal_),
    options (options_)
{
    //  Create the engine object for this connection.
    engine = new (std::nothrow) zmq_engine_t (parent_, fd_, options,
        reconnect_, protocol_, address_);
    zmq_assert (engine);
}

zmq::zmq_init_t::~zmq_init_t ()
{
    if (engine)
        delete engine;
}

bool zmq::zmq_init_t::read (::zmq_msg_t *msg_)
{
    //  If the identity was already sent, do nothing.
    if (sent)
        return false;

    //  Send the identity.
    int rc = zmq_msg_init_size (msg_, options.identity.size ());
    zmq_assert (rc == 0);
    memcpy (zmq_msg_data (msg_), options.identity.c_str (),
        options.identity.size ());
    sent = true;

    //  If initialisation is done, pass the engine to the session and
    //  destroy the init object.
    finalise ();

    return true;
}

bool zmq::zmq_init_t::write (::zmq_msg_t *msg_)
{
    //  If identity was already received, we are not interested
    //  in subsequent messages.
    if (received)
        return false;

    //  Retreieve the remote identity. If it's empty, generate a unique name.
    if (!zmq_msg_size (msg_)) {
        unsigned char identity [uuid_t::uuid_blob_len + 1];
        identity [0] = 0;
        memcpy (identity + 1, uuid_t ().to_blob (), uuid_t::uuid_blob_len);
        peer_identity.assign (identity, uuid_t::uuid_blob_len + 1);
    }
    else {
        peer_identity.assign ((const unsigned char*) zmq_msg_data (msg_),
            zmq_msg_size (msg_));
    }

    received = true;

    return true;
}

void zmq::zmq_init_t::flush ()
{
    //  Check if there's anything to flush.
    if (!received)
        return;

    //  If initialisation is done, pass the engine to the session and
    //  destroy the init object.
    finalise ();
}

void zmq::zmq_init_t::detach (owned_t *reconnecter_)
{
    //  This function is called by engine when disconnection occurs.

    //  If required, launch the reconnecter.
    if (reconnecter_) {
        send_plug (reconnecter_);
        send_own (owner, reconnecter_);
    }

    //  The engine will destroy itself, so let's just drop the pointer here and
    //  start termination of the init object.
    engine = NULL;
    term ();
}

zmq::io_thread_t *zmq::zmq_init_t::get_io_thread ()
{
    return choose_io_thread (options.affinity);
}

class zmq::socket_base_t *zmq::zmq_init_t::get_owner ()
{
    return owner;
}

uint64_t zmq::zmq_init_t::get_ordinal ()
{
    return session_ordinal;
}

void zmq::zmq_init_t::process_plug ()
{
    zmq_assert (engine);
    engine->plug (this);
}

void zmq::zmq_init_t::process_unplug ()
{
    if (engine)
        engine->unplug ();
}

void zmq::zmq_init_t::finalise ()
{
    if (sent && received) {

        //  Disconnect the engine from the init object.
        engine->unplug ();

        session_t *session = NULL;
        
        //  If we have the session ordinal, let's use it to find the session.
        //  If it is not found, it means socket is already being shut down
        //  and the session have been deallocated.
        //  TODO: We should check whether the name of the peer haven't changed
        //  upon reconnection.
        if (session_ordinal) {
            session = owner->find_session (session_ordinal);
            if (!session) {
                term ();
                return;
            }
        }
        else {

            //  If the peer has a unique name, find the associated session.
            //  If it does not exist, create it.
            zmq_assert (!peer_identity.empty ());
            session = owner->find_session (peer_identity);
            if (!session) {
                session = new (std::nothrow) session_t (
                    choose_io_thread (options.affinity), owner, options,
                    peer_identity);
                zmq_assert (session);
                send_plug (session);
                send_own (owner, session);

                //  Reserve a sequence number for following 'attach' command.
                session->inc_seqnum ();
            }
        }

        //  No need to increment seqnum as it was already incremented above.
        send_attach (session, engine, peer_identity, false);

        //  Destroy the init object.
        engine = NULL;
        term ();
    }
}
