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
#include "poll.hpp"
#if defined ZMQ_IOTHREAD_POLLER_USE_POLL

#include <sys/types.h>
#include <sys/time.h>
#include <poll.h>
#include <algorithm>

#include "poll.hpp"
#include "err.hpp"
#include "config.hpp"
#include "i_poll_events.hpp"

zmq::poll_t::poll_t (const zmq::thread_ctx_t &ctx_) :
    worker_poller_base_t (ctx_),
    retired (false)
{
}

zmq::poll_t::~poll_t ()
{
    stop_worker ();
}

zmq::poll_t::handle_t zmq::poll_t::add_fd (fd_t fd_, i_poll_events *events_)
{
    check_thread ();
    zmq_assert (fd_ != retired_fd);

    //  If the file descriptor table is too small expand it.
    fd_table_t::size_type sz = fd_table.size ();
    if (sz <= (fd_table_t::size_type) fd_) {
        fd_table.resize (fd_ + 1);
        while (sz != (fd_table_t::size_type) (fd_ + 1)) {
            fd_table[sz].index = retired_fd;
            ++sz;
        }
    }

    pollfd pfd = {fd_, 0, 0};
    pollset.push_back (pfd);
    zmq_assert (fd_table[fd_].index == retired_fd);

    fd_table[fd_].index = pollset.size () - 1;
    fd_table[fd_].events = events_;

    //  Increase the load metric of the thread.
    adjust_load (1);

    return fd_;
}

void zmq::poll_t::rm_fd (handle_t handle_)
{
    check_thread ();
    fd_t index = fd_table[handle_].index;
    zmq_assert (index != retired_fd);

    //  Mark the fd as unused.
    pollset[index].fd = retired_fd;
    fd_table[handle_].index = retired_fd;
    retired = true;

    //  Decrease the load metric of the thread.
    adjust_load (-1);
}

void zmq::poll_t::set_pollin (handle_t handle_)
{
    check_thread ();
    fd_t index = fd_table[handle_].index;
    pollset[index].events |= POLLIN;
}

void zmq::poll_t::reset_pollin (handle_t handle_)
{
    check_thread ();
    fd_t index = fd_table[handle_].index;
    pollset[index].events &= ~((short) POLLIN);
}

void zmq::poll_t::set_pollout (handle_t handle_)
{
    check_thread ();
    fd_t index = fd_table[handle_].index;
    pollset[index].events |= POLLOUT;
}

void zmq::poll_t::reset_pollout (handle_t handle_)
{
    check_thread ();
    fd_t index = fd_table[handle_].index;
    pollset[index].events &= ~((short) POLLOUT);
}

void zmq::poll_t::stop ()
{
    check_thread ();
    //  no-op... thread is stopped when no more fds or timers are registered
}

int zmq::poll_t::max_fds ()
{
    return -1;
}

void zmq::poll_t::loop ()
{
    while (true) {
        //  Execute any due timers.
        int timeout = (int) execute_timers ();

        cleanup_retired ();

        if (pollset.empty ()) {
            zmq_assert (get_load () == 0);

            if (timeout == 0)
                break;

            // TODO sleep for timeout
            continue;
        }

        //  Wait for events.
        int rc = poll (&pollset[0], static_cast<nfds_t> (pollset.size ()),
                       timeout ? timeout : -1);
        if (rc == -1) {
            errno_assert (errno == EINTR);
            continue;
        }

        //  If there are no events (i.e. it's a timeout) there's no point
        //  in checking the pollset.
        if (rc == 0)
            continue;

        for (pollset_t::size_type i = 0; i != pollset.size (); i++) {
            zmq_assert (!(pollset[i].revents & POLLNVAL));
            if (pollset[i].fd == retired_fd)
                continue;
            if (pollset[i].revents & (POLLERR | POLLHUP))
                fd_table[pollset[i].fd].events->in_event ();
            if (pollset[i].fd == retired_fd)
                continue;
            if (pollset[i].revents & POLLOUT)
                fd_table[pollset[i].fd].events->out_event ();
            if (pollset[i].fd == retired_fd)
                continue;
            if (pollset[i].revents & POLLIN)
                fd_table[pollset[i].fd].events->in_event ();
        }
    }
}

void zmq::poll_t::cleanup_retired ()
{
    //  Clean up the pollset and update the fd_table accordingly.
    if (retired) {
        pollset_t::size_type i = 0;
        while (i < pollset.size ()) {
            if (pollset[i].fd == retired_fd)
                pollset.erase (pollset.begin () + i);
            else {
                fd_table[pollset[i].fd].index = i;
                i++;
            }
        }
        retired = false;
    }
}


#endif
