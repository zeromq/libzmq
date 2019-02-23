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
#include "kqueue.hpp"
#if defined ZMQ_IOTHREAD_POLLER_USE_KQUEUE

#include <sys/time.h>
#include <sys/types.h>
#include <sys/event.h>
#include <stdlib.h>
#include <unistd.h>
#include <algorithm>
#include <new>

#include "macros.hpp"
#include "kqueue.hpp"
#include "err.hpp"
#include "config.hpp"
#include "i_poll_events.hpp"
#include "likely.hpp"

//  NetBSD defines (struct kevent).udata as intptr_t, everyone else
//  as void *.
#if defined ZMQ_HAVE_NETBSD
#define kevent_udata_t intptr_t
#else
#define kevent_udata_t void *
#endif

zmq::kqueue_t::kqueue_t (const zmq::thread_ctx_t &ctx_) :
    worker_poller_base_t (ctx_)
{
    //  Create event queue
    kqueue_fd = kqueue ();
    errno_assert (kqueue_fd != -1);
#ifdef HAVE_FORK
    pid = getpid ();
#endif
}

zmq::kqueue_t::~kqueue_t ()
{
    stop_worker ();
    close (kqueue_fd);
}

void zmq::kqueue_t::kevent_add (fd_t fd_, short filter_, void *udata_)
{
    check_thread ();
    struct kevent ev;

    EV_SET (&ev, fd_, filter_, EV_ADD, 0, 0, (kevent_udata_t) udata_);
    int rc = kevent (kqueue_fd, &ev, 1, NULL, 0, NULL);
    errno_assert (rc != -1);
}

void zmq::kqueue_t::kevent_delete (fd_t fd_, short filter_)
{
    struct kevent ev;

    EV_SET (&ev, fd_, filter_, EV_DELETE, 0, 0, 0);
    int rc = kevent (kqueue_fd, &ev, 1, NULL, 0, NULL);
    errno_assert (rc != -1);
}

zmq::kqueue_t::handle_t zmq::kqueue_t::add_fd (fd_t fd_,
                                               i_poll_events *reactor_)
{
    check_thread ();
    poll_entry_t *pe = new (std::nothrow) poll_entry_t;
    alloc_assert (pe);

    pe->fd = fd_;
    pe->flag_pollin = 0;
    pe->flag_pollout = 0;
    pe->reactor = reactor_;

    adjust_load (1);

    return pe;
}

void zmq::kqueue_t::rm_fd (handle_t handle_)
{
    check_thread ();
    poll_entry_t *pe = (poll_entry_t *) handle_;
    if (pe->flag_pollin)
        kevent_delete (pe->fd, EVFILT_READ);
    if (pe->flag_pollout)
        kevent_delete (pe->fd, EVFILT_WRITE);
    pe->fd = retired_fd;
    retired.push_back (pe);

    adjust_load (-1);
}

void zmq::kqueue_t::set_pollin (handle_t handle_)
{
    check_thread ();
    poll_entry_t *pe = (poll_entry_t *) handle_;
    if (likely (!pe->flag_pollin)) {
        pe->flag_pollin = true;
        kevent_add (pe->fd, EVFILT_READ, pe);
    }
}

void zmq::kqueue_t::reset_pollin (handle_t handle_)
{
    check_thread ();
    poll_entry_t *pe = (poll_entry_t *) handle_;
    if (likely (pe->flag_pollin)) {
        pe->flag_pollin = false;
        kevent_delete (pe->fd, EVFILT_READ);
    }
}

void zmq::kqueue_t::set_pollout (handle_t handle_)
{
    check_thread ();
    poll_entry_t *pe = (poll_entry_t *) handle_;
    if (likely (!pe->flag_pollout)) {
        pe->flag_pollout = true;
        kevent_add (pe->fd, EVFILT_WRITE, pe);
    }
}

void zmq::kqueue_t::reset_pollout (handle_t handle_)
{
    check_thread ();
    poll_entry_t *pe = (poll_entry_t *) handle_;
    if (likely (pe->flag_pollout)) {
        pe->flag_pollout = false;
        kevent_delete (pe->fd, EVFILT_WRITE);
    }
}

void zmq::kqueue_t::stop ()
{
}

int zmq::kqueue_t::max_fds ()
{
    return -1;
}

void zmq::kqueue_t::loop ()
{
    while (true) {
        //  Execute any due timers.
        int timeout = (int) execute_timers ();

        if (get_load () == 0) {
            if (timeout == 0)
                break;

            // TODO sleep for timeout
            continue;
        }

        //  Wait for events.
        struct kevent ev_buf[max_io_events];
        timespec ts = {timeout / 1000, (timeout % 1000) * 1000000};
        int n = kevent (kqueue_fd, NULL, 0, &ev_buf[0], max_io_events,
                        timeout ? &ts : NULL);
#ifdef HAVE_FORK
        if (unlikely (pid != getpid ())) {
            //printf("zmq::kqueue_t::loop aborting on forked child %d\n", (int)getpid());
            // simply exit the loop in a forked process.
            return;
        }
#endif
        if (n == -1) {
            errno_assert (errno == EINTR);
            continue;
        }

        for (int i = 0; i < n; i++) {
            poll_entry_t *pe = (poll_entry_t *) ev_buf[i].udata;

            if (pe->fd == retired_fd)
                continue;
            if (ev_buf[i].flags & EV_EOF)
                pe->reactor->in_event ();
            if (pe->fd == retired_fd)
                continue;
            if (ev_buf[i].filter == EVFILT_WRITE)
                pe->reactor->out_event ();
            if (pe->fd == retired_fd)
                continue;
            if (ev_buf[i].filter == EVFILT_READ)
                pe->reactor->in_event ();
        }

        //  Destroy retired event sources.
        for (retired_t::iterator it = retired.begin (); it != retired.end ();
             ++it) {
            LIBZMQ_DELETE (*it);
        }
        retired.clear ();
    }
}

#endif
