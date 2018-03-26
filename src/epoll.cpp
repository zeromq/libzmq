/*
    Copyright (c) 2007-2016 Contributors as noted in the AUTHORS file

    This file is part of libzmq, the ZeroMQ core engine in C++.

    libzmq is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License (LGPL) as published
    by the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    As a special exception, the Contributors give you permission to link
    this library with independent modules to produce an executable,
    regardless of the license terms of these independent modules, and to
    copy and distribute the resulting executable under terms of your choice,
    provided that you also meet, for each linked independent module, the
    terms and conditions of the license of that module. An independent
    module is a module which is not derived from or based on this library.
    If you modify this library, you must extend this exception to your
    version of the library.

    libzmq is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
    FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
    License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "precompiled.hpp"
#include "epoll.hpp"
#if defined ZMQ_USE_EPOLL

#include <sys/epoll.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <algorithm>
#include <new>

#include "macros.hpp"
#include "epoll.hpp"
#include "err.hpp"
#include "config.hpp"
#include "i_poll_events.hpp"

const zmq::epoll_base_t::handle_t zmq::epoll_base_t::handle_invalid = NULL;

zmq::epoll_t::epoll_t (const zmq::thread_ctx_t &ctx_) :
    worker_poller_base_t (ctx_),
    epoll_base_t ()
{
}

zmq::epoll_t::~epoll_t ()
{
    //  Wait till the worker thread exits.
    stop_worker ();
}

void zmq::epoll_t::loop ()
{
    int timeout;
    do
    {
      //  Execute any due timers.
      timeout = (int) execute_timers ();
      timeout = timeout ? timeout : -1;
    }
    while (wait (timeout) != -2);
}

void zmq::epoll_t::stop ()
{
    check_thread ();
}

void zmq::epoll_t::check_thread ()
{
    worker_poller_base_t::check_thread();
}

zmq::epoll_base_t::epoll_base_t ()
{
#ifdef ZMQ_USE_EPOLL_CLOEXEC
    //  Setting this option result in sane behaviour when exec() functions
    //  are used. Old sockets are closed and don't block TCP ports, avoid
    //  leaks, etc.
    epoll_fd = epoll_create1 (EPOLL_CLOEXEC);
#else
    epoll_fd = epoll_create (1);
#endif
    errno_assert (epoll_fd != -1);
}

zmq::epoll_base_t::~epoll_base_t ()
{
    close (epoll_fd);
    for (retired_t::iterator it = retired.begin (); it != retired.end ();
         ++it) {
        LIBZMQ_DELETE (*it);
    }
}

zmq::epoll_base_t::handle_t zmq::epoll_base_t::add_fd (fd_t fd_, i_poll_events *events_)
{
    check_thread ();
    poll_entry_t *pe = new (std::nothrow) poll_entry_t;
    alloc_assert (pe);

    //  The memset is not actually needed. It's here to prevent debugging
    //  tools to complain about using uninitialised memory.
    memset (pe, 0, sizeof (poll_entry_t));

    pe->fd = fd_;
    pe->ev.events = 0;
    pe->ev.data.ptr = pe;
    pe->events = events_;

    int rc = epoll_ctl (epoll_fd, EPOLL_CTL_ADD, fd_, &pe->ev);
    errno_assert (rc != -1);

    //  Increase the load metric of the thread.
    adjust_load (1);

    return (handle_t) (intptr_t) pe;
}

void zmq::epoll_base_t::rm_fd (handle_t handle_)
{
    check_thread ();
    poll_entry_t *pe = (poll_entry_t *) handle_;
    int rc = epoll_ctl (epoll_fd, EPOLL_CTL_DEL, pe->fd, &pe->ev);
    errno_assert (rc != -1);
    pe->fd = retired_fd;
    retired_sync.lock ();
    retired.push_back (pe);
    retired_sync.unlock ();

    //  Decrease the load metric of the thread.
    adjust_load (-1);
}

void zmq::epoll_base_t::set_pollin (handle_t handle_)
{
    check_thread ();
    poll_entry_t *pe = (poll_entry_t *) handle_;
    pe->ev.events |= EPOLLIN;
    int rc = epoll_ctl (epoll_fd, EPOLL_CTL_MOD, pe->fd, &pe->ev);
    errno_assert (rc != -1);
}

void zmq::epoll_base_t::reset_pollin (handle_t handle_)
{
    check_thread ();
    poll_entry_t *pe = (poll_entry_t *) handle_;
    pe->ev.events &= ~((short) EPOLLIN);
    int rc = epoll_ctl (epoll_fd, EPOLL_CTL_MOD, pe->fd, &pe->ev);
    errno_assert (rc != -1);
}

void zmq::epoll_base_t::set_pollout (handle_t handle_)
{
    check_thread ();
    poll_entry_t *pe = (poll_entry_t *) handle_;
    pe->ev.events |= EPOLLOUT;
    int rc = epoll_ctl (epoll_fd, EPOLL_CTL_MOD, pe->fd, &pe->ev);
    errno_assert (rc != -1);
}

void zmq::epoll_base_t::reset_pollout (handle_t handle_)
{
    check_thread ();
    poll_entry_t *pe = (poll_entry_t *) handle_;
    pe->ev.events &= ~((short) EPOLLOUT);
    int rc = epoll_ctl (epoll_fd, EPOLL_CTL_MOD, pe->fd, &pe->ev);
    errno_assert (rc != -1);
}

int zmq::epoll_base_t::max_fds ()
{
    return -1;
}

int zmq::epoll_base_t::wait (int timeout)
{
    epoll_event ev_buf[max_io_events];

    if (get_load () == 0) {
        if (timeout <= 0)
            return -2;

        // TODO sleep for timeout
        return 0;
    }

    //  Wait for events.
    int n = epoll_wait (epoll_fd, &ev_buf[0], max_io_events, timeout);
    if (n == -1) {
        errno_assert (errno == EINTR);
        return -1;
    }

    for (int i = 0; i < n; i++) {
        poll_entry_t *pe = ((poll_entry_t *) ev_buf[i].data.ptr);

        if (pe->fd == retired_fd)
            continue;
        if (ev_buf[i].events & (EPOLLERR | EPOLLHUP))
            pe->events->err_event ((i_poll_events::handle_t) pe);
        if (pe->fd == retired_fd)
            continue;
        if (ev_buf[i].events & EPOLLOUT)
            pe->events->out_event ((i_poll_events::handle_t) pe);
        if (pe->fd == retired_fd)
            continue;
        if (ev_buf[i].events & EPOLLIN)
            pe->events->in_event ((i_poll_events::handle_t) pe);
    }

    //  Destroy retired event sources.
    retired_sync.lock ();
    for (retired_t::iterator it = retired.begin (); it != retired.end ();
         ++it) {
        LIBZMQ_DELETE (*it);
    }
    retired.clear ();
    retired_sync.unlock ();

    return n;
}

void zmq::epoll_base_t::check_thread ()
{
}

#endif
