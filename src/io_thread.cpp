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

#include "../include/zs.h"

#include "io_thread.hpp"
#include "command.hpp"
#include "platform.hpp"
#include "err.hpp"
#include "command.hpp"
#include "epoll.hpp"
#include "poll.hpp"
#include "select.hpp"
#include "devpoll.hpp"
#include "kqueue.hpp"
#include "dispatcher.hpp"
#include "session.hpp"
#include "simple_semaphore.hpp"
#include "session.hpp"

zs::io_thread_t::io_thread_t (dispatcher_t *dispatcher_, int thread_slot_) :
    object_t (dispatcher_, thread_slot_)
{
#if defined ZS_FORCE_SELECT
    poller = new select_t;
#elif defined ZS_FORCE_POLL
    poller = new poll_t;
#elif defined ZS_FORCE_EPOLL
    poller = new epoll_t;
#elif defined ZS_FORCE_DEVPOLL
    poller = new devpoll_t;
#elif defined ZS_FORCE_KQUEUE
    poller = new kqueue_t;
#elif defined ZS_HAVE_LINUX
    poller = new epoll_t;
#elif defined ZS_HAVE_WINDOWS
    poller = new select_t;
#elif defined ZS_HAVE_FREEBSD
    poller = new kqueue_t;
#elif defined ZS_HAVE_OPENBSD
    poller = new kqueue_t;
#elif defined ZS_HAVE_SOLARIS
    poller = new devpoll_t;
#elif defined ZS_HAVE_OSX
    poller = new kqueue_t;
#elif defined ZS_HAVE_QNXNTO
    poller = new poll_t;
#elif defined ZS_HAVE_AIX
    poller = new poll_t;
#elif defined ZS_HAVE_HPUX
    poller = new devpoll_t;
#elif defined ZS_HAVE_OPENVMS
    poller = new select_t;
#else
#error Unsupported platform
#endif
    zs_assert (poller);

    signaler_handle = poller->add_fd (signaler.get_fd (), this);
    poller->set_pollin (signaler_handle);
}

void zs::io_thread_t::shutdown ()
{
    //  Deallocate all the sessions associated with the thread.
    while (!sessions.empty ())
        sessions [0]->shutdown ();

    delete this;
}

zs::io_thread_t::~io_thread_t ()
{
    delete poller;
}

void zs::io_thread_t::start ()
{
    //  Start the underlying I/O thread.
    poller->start ();
}

void zs::io_thread_t::stop ()
{
    send_stop ();
}

void zs::io_thread_t::join ()
{
    poller->join ();
}

zs::i_signaler *zs::io_thread_t::get_signaler ()
{
    return &signaler;
}

int zs::io_thread_t::get_load ()
{
    return poller->get_load ();
}

void zs::io_thread_t::in_event ()
{
    //  Find out which threads are sending us commands.
    fd_signaler_t::signals_t signals = signaler.check ();
    zs_assert (signals);

    //  Iterate through all the threads in the process and find out
    //  which of them sent us commands.
    int slot_count = thread_slot_count ();
    for (int source_thread_slot = 0;
          source_thread_slot != slot_count; source_thread_slot++) {
        if (signals & (fd_signaler_t::signals_t (1) << source_thread_slot)) {

            //  Read all the commands from particular thread.
            command_t cmd;
            while (dispatcher->read (source_thread_slot, thread_slot, &cmd))
                cmd.destination->process_command (cmd);
        }
    }
}

void zs::io_thread_t::out_event ()
{
    //  We are never polling for POLLOUT here. This function is never called.
    zs_assert (false);
}

void zs::io_thread_t::timer_event ()
{
    //  No timers here. This function is never called.
    zs_assert (false);
}

void zs::io_thread_t::attach_session (session_t *session_)
{
    session_->set_index (sessions.size ());
    sessions.push_back (session_); 
}

void zs::io_thread_t::detach_session (session_t *session_)
{
    //  O(1) removal of the session from the list.
    sessions_t::size_type i = session_->get_index ();
    sessions [i] = sessions [sessions.size () - 1];
    sessions [i]->set_index (i);
    sessions.pop_back ();
}

zs::i_poller *zs::io_thread_t::get_poller ()
{
    zs_assert (poller);
    return poller;
}

void zs::io_thread_t::process_stop ()
{
    poller->rm_fd (signaler_handle);
    poller->stop ();
}
