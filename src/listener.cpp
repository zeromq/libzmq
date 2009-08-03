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

#include "listener.hpp"
#include "simple_semaphore.hpp"
#include "zmq_tcp_engine.hpp"
#include "io_thread.hpp"
#include "session_stub.hpp"
#include "session.hpp"
#include "err.hpp"
#include "dummy_aggregator.hpp"
#include "dummy_distributor.hpp"

zmq::listener_t::listener_t (io_thread_t *thread_, const char *addr_,
      session_t *peer_, bool has_in_, bool has_out_, uint64_t taskset_) :
    io_object_t (thread_),
    poller (NULL),
    addr (addr_),
    peer (peer_),
    taskset (taskset_),
    has_in (has_in_),
    has_out (has_out_)
{
}

void zmq::listener_t::terminate ()
{
    for (session_stubs_t::size_type i = 0; i != session_stubs.size (); i++)
        session_stubs [i]->terminate ();
    delete this;
}

void zmq::listener_t::shutdown ()
{
    for (session_stubs_t::size_type i = 0; i != session_stubs.size (); i++)
        session_stubs [i]->shutdown ();
    delete this;
}

zmq::listener_t::~listener_t ()
{
}

void zmq::listener_t::got_identity (session_stub_t *session_stub_,
    const char *identity_)
{
    //  Get the engine allready disconnected from the stub and poller.
    i_engine *engine = session_stub_->detach_engine ();
    zmq_assert (engine);

    //  Find the corresponding session.
    session_t *session;
    sessions_t::iterator it = sessions.find (identity_);

    //  Destroy the stub.
    int i = session_stub_->get_index ();
    session_stubs [i] = session_stubs [session_stubs.size () - 1];
    session_stubs [i]->set_index (i);
    session_stubs.pop_back ();
    session_stub_->terminate ();

    //  If there's no session with the specified identity, create one.
    if (it != sessions.end ()) {
        session = it->second;
        session->inc_seqnum ();
    }
    else {

        //  Choose an I/O thread with the least load to handle the new session.
        io_thread_t *io_thread = choose_io_thread (taskset);

        //  Create the session and bind it to the I/O thread and peer. Make
        //  sure that the peer session won't get deallocated till it processes
        //  the subsequent bind command.
        i_mux *mux = new dummy_aggregator_t;
        zmq_assert (mux);
        i_demux *demux = new dummy_distributor_t;
        zmq_assert (demux);
        session = new session_t (io_thread, io_thread, mux, demux, false, true);
        zmq_assert (session);
        session->inc_seqnum ();
        session->inc_seqnum ();
        peer->inc_seqnum ();
        send_reg_and_bind (session, peer, has_in, has_out);
    }

    //  Attach the engine to the session.
    send_engine (session, engine);
}

void zmq::listener_t::process_reg (simple_semaphore_t *smph_)
{
    zmq_assert (!poller);
    poller = get_poller ();

    //  Open the listening socket.
    int rc = tcp_listener.open (addr.c_str ());
    zmq_assert (rc == 0);

    //  Unlock the application thread that created the listener.
    if (smph_)
        smph_->post ();

    //  Start polling for incoming connections.
    handle = poller->add_fd (tcp_listener.get_fd (), this);
    poller->set_pollin (handle);
}

void zmq::listener_t::process_unreg (simple_semaphore_t *smph_)
{
    //  Disassociate listener from the poller.
    zmq_assert (poller);
    poller->rm_fd (handle);
    poller = NULL;

    //  Unlock the application thread closing the listener.
    if (smph_)
        smph_->post ();
}

void zmq::listener_t::in_event ()
{
    fd_t fd = tcp_listener.accept ();

    //  If connection was reset by the peer in the meantime, just ignore it.
    //  TODO: Handle specific errors like ENFILE/EMFILE etc.
    if (fd == retired_fd)
        return;

    //  Create an session stub for the engine to take care for it till its
    //  identity is retreived.
    session_stub_t *session_stub = new session_stub_t (this);
    zmq_assert (session_stub);
    session_stub->set_index (session_stubs.size ());
    session_stubs.push_back (session_stub);

    //  Create an engine to encaspulate the socket. Engine will register itself
    //  with the stub so the stub will be able to free it in case of shutdown.
    zmq_tcp_engine_t *engine = new zmq_tcp_engine_t (fd);
    zmq_assert (engine);
    engine->attach (poller, session_stub);
}

void zmq::listener_t::out_event ()
{
    zmq_assert (false);
}

void zmq::listener_t::timer_event ()
{
    zmq_assert (false);
}


