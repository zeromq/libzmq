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

#include "connecter.hpp"
#include "io_thread.hpp"
#include "session.hpp"
#include "err.hpp"
#include "simple_semaphore.hpp"
#include "zmq_tcp_engine.hpp"

zs::connecter_t::connecter_t (io_thread_t *thread_, const char *addr_,
      session_t *session_) :
    io_object_t (thread_),
    state (idle),
    poller (NULL),
    session (session_),
    addr (addr_),
    identity ("abcde"),
    engine (NULL)
{
}

void zs::connecter_t::terminate ()
{
    delete this;
}

void zs::connecter_t::shutdown ()
{
    delete this;
}

zs::connecter_t::~connecter_t ()
{
}

void zs::connecter_t::process_reg (simple_semaphore_t *smph_)
{
    //  Fet poller pointer for further use.
    zs_assert (!poller);
    poller = get_poller ();

    //  Ask the session to register itself with the I/O thread. Note that
    //  the session is living in the same I/O thread, thus this results
    //  in a synchronous call.
    session->inc_seqnum ();
    send_reg (session, NULL);

    //  Unlock the application thread that created the connecter.
    if (smph_)
        smph_->post ();

    //  Manually trigger timer event which will launch asynchronous connect.
    state = waiting;
    timer_event ();
}

void zs::connecter_t::process_unreg (simple_semaphore_t *smph_)
{
    //  Unregister connecter/engine from the poller.
    zs_assert (poller);
    if (state == connecting)
        poller->rm_fd (handle);
    else if (state == waiting)
        poller->cancel_timer (this);
    else if (state == sending)
        engine->terminate ();

    //  Unlock the application thread closing the connecter.
    if (smph_)
        smph_->post ();
}

void zs::connecter_t::in_event ()
{
    //  Error occured in asynchronous connect. Retry to connect after a while.
    if (state == connecting) {
        fd_t fd = tcp_connecter.connect ();
        zs_assert (fd == retired_fd);
        poller->rm_fd (handle);
        poller->add_timer (this);
        state = waiting;
        return;
    }

    zs_assert (false);
}

void zs::connecter_t::out_event ()
{
    if (state == connecting) {

        fd_t fd = tcp_connecter.connect ();
        if (fd == retired_fd) {
            poller->rm_fd (handle);
            poller->add_timer (this);
            state = waiting;
            return;
        }

        poller->rm_fd (handle);
        engine = new zmq_tcp_engine_t (fd);
        zs_assert (engine);
        engine->attach (poller, this);
        state = sending;
        return;
    }

    zs_assert (false);
}

void zs::connecter_t::timer_event ()
{
    zs_assert (state == waiting);

    //  Initiate async connect and start polling for its completion. If async
    //  connect fails instantly, try to reconnect after a while.
    int rc = tcp_connecter.open (addr.c_str ());
    if (rc == 0) {
        state = connecting;
        in_event ();
    }
    else if (rc == 1) {
        handle = poller->add_fd (tcp_connecter.get_fd (), this);
        poller->set_pollout (handle);
        state = connecting;
    }
    else {
        poller->add_timer (this);
        state = waiting;
    }
}

void zs::connecter_t::set_engine (struct i_engine *engine_)
{
    engine = engine_;
}

bool zs::connecter_t::read (zs_msg *msg_)
{
    zs_assert (state == sending);

    //  Deallocate old content of the message just in case.
    zs_msg_close (msg_);

    //  Send the identity.
    zs_msg_init_size (msg_, identity.size ());
    memcpy (zs_msg_data (msg_), identity.c_str (), identity.size ());

    //  Ask engine to unregister from the poller.
    i_engine *e = engine;
    engine->detach ();

    //  Attach the engine to the session. (Note that this is actually
    //  a synchronous call.
    session->inc_seqnum ();
    send_engine (session, e);

    state = idle;

    return true;    
}

bool zs::connecter_t::write (struct zs_msg *msg_)
{
    //  No incoming messages are accepted till identity is sent.
    return false;
}

void zs::connecter_t::flush ()
{
    //  No incoming messages are accepted till identity is sent.
}
