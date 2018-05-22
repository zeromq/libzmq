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
#include "pollset.hpp"
#if defined ZMQ_IOTHREAD_POLLER_USE_POLLSET

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <algorithm>
#include <new>

#include "macros.hpp"
#include "err.hpp"
#include "config.hpp"
#include "i_poll_events.hpp"

zmq::pollset_t::pollset_t (const zmq::thread_ctx_t &ctx_) :
    ctx (ctx_),
    stopping (false)
{
    pollset_fd = pollset_create (-1);
    errno_assert (pollset_fd != -1);
}

zmq::pollset_t::~pollset_t ()
{
    //  Wait till the worker thread exits.
    worker.stop ();

    pollset_destroy (pollset_fd);
    for (retired_t::iterator it = retired.begin (); it != retired.end (); ++it)
        LIBZMQ_DELETE (*it);
}

zmq::pollset_t::handle_t zmq::pollset_t::add_fd (fd_t fd_,
                                                 i_poll_events *events_)
{
    poll_entry_t *pe = new (std::nothrow) poll_entry_t;
    alloc_assert (pe);

    pe->fd = fd_;
    pe->flag_pollin = false;
    pe->flag_pollout = false;
    pe->events = events_;

    struct poll_ctl pc;
    pc.fd = fd_;
    pc.cmd = PS_ADD;
    pc.events = 0;

    int rc = pollset_ctl (pollset_fd, &pc, 1);
    errno_assert (rc != -1);

    //  Increase the load metric of the thread.
    adjust_load (1);

    if (fd_ >= fd_table.size ()) {
        fd_table.resize (fd_ + 1, NULL);
    }
    fd_table[fd_] = pe;
    return pe;
}

void zmq::pollset_t::rm_fd (handle_t handle_)
{
    poll_entry_t *pe = (poll_entry_t *) handle_;

    struct poll_ctl pc;
    pc.fd = pe->fd;
    pc.cmd = PS_DELETE;
    pc.events = 0;
    pollset_ctl (pollset_fd, &pc, 1);

    fd_table[pe->fd] = NULL;

    pe->fd = retired_fd;
    retired.push_back (pe);

    //  Decrease the load metric of the thread.
    adjust_load (-1);
}

void zmq::pollset_t::set_pollin (handle_t handle_)
{
    poll_entry_t *pe = (poll_entry_t *) handle_;
    if (likely (!pe->flag_pollin)) {
        struct poll_ctl pc;
        pc.fd = pe->fd;
        pc.cmd = PS_MOD;
        pc.events = POLLIN;

        const int rc = pollset_ctl (pollset_fd, &pc, 1);
        errno_assert (rc != -1);

        pe->flag_pollin = true;
    }
}

void zmq::pollset_t::reset_pollin (handle_t handle_)
{
    poll_entry_t *pe = (poll_entry_t *) handle_;
    if (unlikely (!pe->flag_pollin)) {
        return;
    }

    struct poll_ctl pc;
    pc.fd = pe->fd;
    pc.events = 0;

    pc.cmd = PS_DELETE;
    int rc = pollset_ctl (pollset_fd, &pc, 1);

    if (pe->flag_pollout) {
        pc.events = POLLOUT;
        pc.cmd = PS_MOD;
        rc = pollset_ctl (pollset_fd, &pc, 1);
        errno_assert (rc != -1);
    }

    pe->flag_pollin = false;
}

void zmq::pollset_t::set_pollout (handle_t handle_)
{
    poll_entry_t *pe = (poll_entry_t *) handle_;
    if (likely (!pe->flag_pollout)) {
        struct poll_ctl pc;
        pc.fd = pe->fd;
        pc.cmd = PS_MOD;
        pc.events = POLLOUT;

        const int rc = pollset_ctl (pollset_fd, &pc, 1);
        errno_assert (rc != -1);

        pe->flag_pollout = true;
    }
}

void zmq::pollset_t::reset_pollout (handle_t handle_)
{
    poll_entry_t *pe = (poll_entry_t *) handle_;
    if (unlikely (!pe->flag_pollout)) {
        return;
    }

    struct poll_ctl pc;
    pc.fd = pe->fd;
    pc.events = 0;

    pc.cmd = PS_DELETE;
    int rc = pollset_ctl (pollset_fd, &pc, 1);
    errno_assert (rc != -1);

    if (pe->flag_pollin) {
        pc.cmd = PS_MOD;
        pc.events = POLLIN;
        rc = pollset_ctl (pollset_fd, &pc, 1);
        errno_assert (rc != -1);
    }
    pe->flag_pollout = false;
}

void zmq::pollset_t::start ()
{
    ctx.start_thread (worker, worker_routine, this);
}

void zmq::pollset_t::stop ()
{
    stopping = true;
}

int zmq::pollset_t::max_fds ()
{
    return -1;
}

void zmq::pollset_t::loop ()
{
    struct pollfd polldata_array[max_io_events];

    while (!stopping) {
        //  Execute any due timers.
        int timeout = (int) execute_timers ();

        //  Wait for events.
        int n = pollset_poll (pollset_fd, polldata_array, max_io_events,
                              timeout ? timeout : -1);
        if (n == -1) {
            errno_assert (errno == EINTR);
            continue;
        }

        for (int i = 0; i < n; i++) {
            poll_entry_t *pe = fd_table[polldata_array[i].fd];
            if (!pe)
                continue;

            if (pe->fd == retired_fd)
                continue;
            if (polldata_array[i].revents & (POLLERR | POLLHUP))
                pe->events->in_event ();
            if (pe->fd == retired_fd)
                continue;
            if (polldata_array[i].revents & POLLOUT)
                pe->events->out_event ();
            if (pe->fd == retired_fd)
                continue;
            if (polldata_array[i].revents & POLLIN)
                pe->events->in_event ();
        }

        //  Destroy retired event sources.
        for (retired_t::iterator it = retired.begin (); it != retired.end ();
             ++it)
            LIBZMQ_DELETE (*it);
        retired.clear ();
    }
}

void zmq::pollset_t::worker_routine (void *arg_)
{
    ((pollset_t *) arg_)->loop ();
}

#endif
