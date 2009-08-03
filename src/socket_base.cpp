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

#include "socket_base.hpp"
#include "app_thread.hpp"
#include "err.hpp"
#include "listener.hpp"
#include "connecter.hpp"
#include "simple_semaphore.hpp"
#include "io_thread.hpp"
#include "io_object.hpp"
#include "session.hpp"
#include "dummy_aggregator.hpp"
#include "dummy_distributor.hpp"

zmq::socket_base_t::socket_base_t (app_thread_t *thread_, session_t *session_) :
    object_t (thread_),
    thread (thread_),
    session (session_),
    has_in (true),
    has_out (true)
{
    session->set_engine (this);
}

void zmq::socket_base_t::shutdown ()
{
    //  Destroy all the I/O objects created from this socket.
    for (io_objects_t::size_type i = 0; i != io_objects.size (); i++)
        io_objects [i]->shutdown ();

    delete this;
}

void zmq::socket_base_t::schedule_terminate ()
{
    //  Terminate is never scheduled on socket engines.
    zmq_assert (false);
}

void zmq::socket_base_t::terminate ()
{
    //  Destroy all the I/O objects created from this socket.
    //  First unregister the object from I/O thread, then terminate it in
    //  this application thread.
    simple_semaphore_t smph;
    for (io_objects_t::size_type i = 0; i != io_objects.size (); i++) {
        send_unreg (io_objects [i], &smph);
        smph.wait ();
        io_objects [i]->terminate ();
    }

    zmq_assert (session);
    session->disconnected ();

    delete this;
}

zmq::socket_base_t::~socket_base_t ()
{
}

void zmq::socket_base_t::disable_in ()
{
    has_in = false;
}

void zmq::socket_base_t::disable_out ()
{
    has_out = false;
}

int zmq::socket_base_t::bind (const char *addr_, zmq_opts *opts_)
{
    thread->process_commands (false);

    std::string addr (addr_);
    std::string::size_type pos = addr.find ("://");
    if (pos == std::string::npos || addr.substr (0, pos) == "zmq.tcp") {

        //  Choose the I/O thread with the least load, create the listener.
        //  Note that same taskset is used to choose the I/O thread to handle
        //  the listening socket and newly created connections.
        //  Note that has_in and has_out are twisted at this place - listener
        //  is going to create peer objects, so the message flows are viewed
        //  from the opposite direction.
        io_thread_t *io_thread = choose_io_thread (opts_ ? opts_->taskset : 0);
        listener_t *listener = new listener_t (io_thread, addr_, session,
            has_out, has_in, opts_ ? opts_->taskset : 0);

        //  Ask it to start interacting with the I/O thread.
        simple_semaphore_t smph;
        send_reg (listener, &smph);

        //  Store the reference to the listener so that it can be terminated
        //  when the socket is closed.
        io_objects.push_back (listener);

        //  Wait while listener is actually registered with the I/O thread.
        smph.wait ();

        return 0;
    }
    else if (addr.substr (0, pos) == "inproc") {

        //  For inproc transport the only thing we have to do is to register
        //  this socket as an inproc endpoint with the supplied name.
        return register_inproc_endpoint (addr.substr (pos + 3).c_str (),
            session);
    }
    else {

        //  Unknown protocol requested.
        errno = EINVAL;
        return -1;
    }
}

int zmq::socket_base_t::connect (const char *addr_, zmq_opts *opts_)
{
    thread->process_commands (false);

    std::string addr (addr_);
    std::string::size_type pos = addr.find ("://");
    if (pos == std::string::npos || addr.substr (0, pos) == "zmq.tcp") {

        //  Choose the I/O thread with the least load, create the connecter and
        //  session.
        io_thread_t *io_thread = choose_io_thread (opts_ ? opts_->taskset : 0);
        i_mux *mux = new dummy_aggregator_t;
        zmq_assert (mux);
        i_demux *demux = new dummy_distributor_t;
        zmq_assert (demux);
        session_t *peer = new session_t (io_thread, io_thread, mux, demux,
            false, true);
        zmq_assert (peer);
        connecter_t *connecter = new connecter_t (io_thread, addr_, peer);
        zmq_assert (connecter);

        //  Increment session's command sequence number so that it won't get
        //  deallocated till the subsequent bind command arrives.
        peer->inc_seqnum ();

        //  Register the connecter (and session) with its I/O thread.
        simple_semaphore_t smph;
        send_reg (connecter, &smph);

        //  Store the reference to the connecter so that it can be terminated
        //  when the socket is closed.
        io_objects.push_back (connecter);

        //  Wait till registration succeeds.
        smph.wait ();

        //  Bind local session with the connecter's session so that messages
        //  can flow in both directions.
        session->bind (peer, has_in, has_out);

        return 0;
    }
    else if (addr.substr (0, pos) == "inproc") {

        //  Get the MD responsible for the address. In case of invalid address
        //  return error.
        object_t *peer = get_inproc_endpoint (addr.substr (pos + 3).c_str ());
        if (!peer) {
            errno = EADDRNOTAVAIL;
            return -1;
        }

        //  Create bidirectional message pipes between this session and
        //  the peer session.
        session->bind (peer, has_in, has_out);

        return 0;
    }
    else {

        //  Unknown protocol requested.
        errno = EINVAL;
        return -1;
    }
}

int zmq::socket_base_t::subscribe (const char *criteria_)
{
    //  No implementation at the moment...
    errno = ENOTSUP;
    return -1;
}

int zmq::socket_base_t::send (zmq_msg *msg_, int flags_)
{
    thread->process_commands (false);
    while (true) {
        if (session->write (msg_))
            return 0;
        if (flags_ & ZMQ_NOBLOCK) {
            errno = EAGAIN;
            return -1;
        }
        thread->process_commands (true);
    }
}

int zmq::socket_base_t::flush ()
{
    thread->process_commands (false);
    session->flush ();
    return 0;
}

int zmq::socket_base_t::recv (zmq_msg *msg_, int flags_)
{
    thread->process_commands (false);
    while (true) {
        if (session->read (msg_))
            return 0;
        if (flags_ & ZMQ_NOBLOCK) {
            errno = EAGAIN;
            return -1;
        }
        thread->process_commands (true);
    }
}

int zmq::socket_base_t::close ()
{
    terminate ();
    return 0;
}

void zmq::socket_base_t::attach (struct i_poller *poller_, i_session *session_)
{
    zmq_assert (false);
}

void zmq::socket_base_t::detach ()
{
    zmq_assert (false);
}

void zmq::socket_base_t::revive ()
{
    //  We can ignore the event safely here.
}

