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
#include <algorithm>

#include "../include/zmq.h"

#include "socket_base.hpp"
#include "app_thread.hpp"
#include "err.hpp"
#include "zmq_listener.hpp"
#include "zmq_connecter.hpp"
#include "io_thread.hpp"
#include "session.hpp"
#include "config.hpp"
#include "owned.hpp"
#include "uuid.hpp"

zmq::socket_base_t::socket_base_t (app_thread_t *parent_) :
    object_t (parent_),
    pending_term_acks (0),
    app_thread (parent_),
    shutting_down (false)
{    
}

zmq::socket_base_t::~socket_base_t ()
{
    shutting_down = true;

    while (true) {

        //  On third pass of the loop there should be no more I/O objects
        //  because all connecters and listerners were destroyed during
        //  the first pass and all engines delivered by delayed 'own' commands
        //  are destroyed during the second pass.
        if (io_objects.empty () && !pending_term_acks)
            break;

        //  Send termination request to all associated I/O objects.
        for (io_objects_t::iterator it = io_objects.begin ();
              it != io_objects.end (); it++)
            send_term (*it);

        //  Move the objects to the list of pending term acks.
        pending_term_acks += io_objects.size ();
        io_objects.clear ();

        //  Process commands till we get all the termination acknowledgements.
        while (pending_term_acks)
            app_thread->process_commands (true);
    }

    //  Check whether there are no session leaks.
    sessions_sync.lock ();
    zmq_assert (sessions.empty ());
    sessions_sync.unlock ();
}

int zmq::socket_base_t::setsockopt (int option_, const void *optval_,
    size_t optvallen_)
{
    switch (option_) {

    case ZMQ_HWM:
        if (optvallen_ != sizeof (int64_t)) {
            errno = EINVAL;
            return -1;
        }
        options.hwm = *((int64_t*) optval_);
        return 0;

    case ZMQ_LWM:
        if (optvallen_ != sizeof (int64_t)) {
            errno = EINVAL;
            return -1;
        }
        options.lwm = *((int64_t*) optval_);
        return 0;

    case ZMQ_SWAP:
        if (optvallen_ != sizeof (int64_t)) {
            errno = EINVAL;
            return -1;
        }
        options.swap = *((int64_t*) optval_);
        return 0;

    case ZMQ_MASK:
        if (optvallen_ != sizeof (int64_t)) {
            errno = EINVAL;
            return -1;
        }
        options.mask = (uint64_t) *((int64_t*) optval_);
        return 0;

    case ZMQ_AFFINITY:
        if (optvallen_ != sizeof (int64_t)) {
            errno = EINVAL;
            return -1;
        }
        options.affinity = (uint64_t) *((int64_t*) optval_);
        return 0;

    case ZMQ_IDENTITY:
        options.identity.assign ((const char*) optval_, optvallen_);
        return 0;

    default:
        errno = EINVAL;
        return -1;
    }
}

int zmq::socket_base_t::bind (const char *addr_)
{
    zmq_listener_t *listener = new zmq_listener_t (
        choose_io_thread (options.affinity), this, options);
    int rc = listener->set_address (addr_);
    if (rc != 0)
        return -1;

    send_plug (listener);
    send_own (this, listener);
    return 0;
}

int zmq::socket_base_t::connect (const char *addr_)
{
    //  Generate a unique name for the session.
    std::string session_name ("#");
    session_name += uuid_t ().to_string ();

    //  Create the session.
    io_thread_t *io_thread = choose_io_thread (options.affinity);
    session_t *session = new session_t (io_thread, this, session_name.c_str ());
    zmq_assert (session);
    send_plug (session);
    send_own (this, session);

    //  Create the connecter object. Supply it with the session name so that
    //  it can bind the new connection to the session once it is established.
    zmq_connecter_t *connecter = new zmq_connecter_t (
        choose_io_thread (options.affinity), this, options,
        session_name.c_str ());
    int rc = connecter->set_address (addr_);
    if (rc != 0) {
        delete connecter;
        return -1;
    }
    send_plug (connecter);
    send_own (this, connecter);

    return 0;
}

int zmq::socket_base_t::send (::zmq_msg_t *msg_, int flags_)
{
    zmq_assert (false);
}

int zmq::socket_base_t::flush ()
{
    zmq_assert (false);
}

int zmq::socket_base_t::recv (::zmq_msg_t *msg_, int flags_)
{
    zmq_assert (false);
}

int zmq::socket_base_t::close ()
{
    app_thread->remove_socket (this);
    delete this;
    return 0;
}

bool zmq::socket_base_t::register_session (const char *name_,
    session_t *session_)
{
    sessions_sync.lock ();
    bool registered = sessions.insert (std::make_pair (name_, session_)).second;
    sessions_sync.unlock ();
    return registered;
}

bool zmq::socket_base_t::unregister_session (const char *name_)
{
    sessions_sync.lock ();
    sessions_t::iterator it = sessions.find (name_);
    bool unregistered = (it != sessions.end ());
    sessions.erase (it);
    sessions_sync.unlock ();
    return unregistered;
}

zmq::session_t *zmq::socket_base_t::find_session (const char *name_)
{
    sessions_sync.lock ();

    sessions_t::iterator it = sessions.find (name_);
    if (it == sessions.end ()) {
        sessions_sync.unlock ();
        return NULL;
    }

    //  Prepare the session for subsequent attach command.
    it->second->inc_seqnum ();

    sessions_sync.unlock ();
    return it->second;    
}

void zmq::socket_base_t::process_own (owned_t *object_)
{
    io_objects.insert (object_);
}

void zmq::socket_base_t::process_term_req (owned_t *object_)
{
    //  When shutting down we can ignore termination requests from owned
    //  objects. They are going to be terminated anyway.
    if (shutting_down)
        return;

    //  If I/O object is well and alive ask it to terminate.
    io_objects_t::iterator it = std::find (io_objects.begin (),
        io_objects.end (), object_);

    //  If not found, we assume that termination request was already sent to
    //  the object so we can sagely ignore the request.
    if (it == io_objects.end ())
        return;

    pending_term_acks++;
    io_objects.erase (it);
    send_term (object_);
}

void zmq::socket_base_t::process_term_ack ()
{
    zmq_assert (pending_term_acks);
    pending_term_acks--;
}
