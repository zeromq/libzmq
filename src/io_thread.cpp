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

#include "../include/zmq.h"

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
#include "context.hpp"
#include "simple_semaphore.hpp"

zmq::io_thread_t::io_thread_t (context_t *context_, int thread_slot_) :
    object_t (context_, thread_slot_)
{
#if defined ZMQ_FORCE_SELECT
    poller = new select_t;
#elif defined ZMQ_FORCE_POLL
    poller = new poll_t;
#elif defined ZMQ_FORCE_EPOLL
    poller = new epoll_t;
#elif defined ZMQ_FORCE_DEVPOLL
    poller = new devpoll_t;
#elif defined ZMQ_FORCE_KQUEUE
    poller = new kqueue_t;
#elif defined ZMQ_HAVE_LINUX
    poller = new epoll_t;
#elif defined ZMQ_HAVE_WINDOWS
    poller = new select_t;
#elif defined ZMQ_HAVE_FREEBSD
    poller = new kqueue_t;
#elif defined ZMQ_HAVE_OPENBSD
    poller = new kqueue_t;
#elif defined ZMQ_HAVE_SOLARIS
    poller = new devpoll_t;
#elif defined ZMQ_HAVE_OSX
    poller = new kqueue_t;
#elif defined ZMQ_HAVE_QNXNTO
    poller = new poll_t;
#elif defined ZMQ_HAVE_AIX
    poller = new poll_t;
#elif defined ZMQ_HAVE_HPUX
    poller = new devpoll_t;
#elif defined ZMQ_HAVE_OPENVMS
    poller = new select_t;
#else
#error Unsupported platform
#endif
    zmq_assert (poller);

    signaler_handle = poller->add_fd (signaler.get_fd (), this);
    poller->set_pollin (signaler_handle);
}

zmq::io_thread_t::~io_thread_t ()
{
    delete poller;
}

void zmq::io_thread_t::start ()
{
    //  Start the underlying I/O thread.
    poller->start ();
}

void zmq::io_thread_t::stop ()
{
    send_stop ();
}

zmq::i_signaler *zmq::io_thread_t::get_signaler ()
{
    return &signaler;
}

int zmq::io_thread_t::get_load ()
{
    return poller->get_load ();
}

void zmq::io_thread_t::in_event ()
{
    //  Find out which threads are sending us commands.
    fd_signaler_t::signals_t signals = signaler.check ();
    zmq_assert (signals);

    //  Iterate through all the threads in the process and find out
    //  which of them sent us commands.
    int slot_count = thread_slot_count ();
    for (int source_thread_slot = 0;
          source_thread_slot != slot_count; source_thread_slot++) {
        if (signals & (fd_signaler_t::signals_t (1) << source_thread_slot)) {

            //  Read all the commands from particular thread.
            command_t cmd;
            while (context->read (source_thread_slot, thread_slot, &cmd))
                cmd.destination->process_command (cmd);
        }
    }
}

void zmq::io_thread_t::out_event ()
{
    //  We are never polling for POLLOUT here. This function is never called.
    zmq_assert (false);
}

void zmq::io_thread_t::timer_event ()
{
    //  No timers here. This function is never called.
    zmq_assert (false);
}

zmq::i_poller *zmq::io_thread_t::get_poller ()
{
    zmq_assert (poller);
    return poller;
}

void zmq::io_thread_t::process_stop ()
{
    poller->rm_fd (signaler_handle);
    poller->stop ();
}
