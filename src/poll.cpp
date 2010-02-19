/*
    Copyright (c) 2007-2010 iMatix Corporation

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

#include "platform.hpp"

#if defined ZMQ_HAVE_LINUX || defined ZMQ_HAVE_FREEBSD ||\
    defined ZMQ_HAVE_OPENBSD || defined ZMQ_HAVE_SOLARIS ||\
    defined ZMQ_HAVE_OSX || defined ZMQ_HAVE_QNXNTO ||\
    defined ZMQ_HAVE_HPUX || defined ZMQ_HAVE_AIX ||\
    defined ZMQ_HAVE_NETBSD

#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <poll.h>
#include <algorithm>

#include "poll.hpp"
#include "err.hpp"
#include "config.hpp"
#include "i_poll_events.hpp"

zmq::poll_t::poll_t () :
    retired (false),
    stopping (false)
{
    //  Get the limit on open file descriptors. Resize fds so that it
    //  can hold all descriptors.
    rlimit rl;
    int rc = getrlimit (RLIMIT_NOFILE, &rl);
    errno_assert (rc != -1);
    fd_table.resize (rl.rlim_cur);

    for (rlim_t i = 0; i < rl.rlim_cur; i ++)
        fd_table [i].index = retired_fd;
}

zmq::poll_t::~poll_t ()
{
    worker.stop ();

    //  Make sure there are no fds registered on shutdown.
    zmq_assert (load.get () == 0);
}

zmq::poll_t::handle_t zmq::poll_t::add_fd (fd_t fd_, i_poll_events *events_)
{
    pollfd pfd = {fd_, 0, 0};
    pollset.push_back (pfd);
    assert (fd_table [fd_].index == retired_fd);

    fd_table [fd_].index = pollset.size() - 1;
    fd_table [fd_].events = events_;

    //  Increase the load metric of the thread.
    load.add (1);

    return fd_;
}

void zmq::poll_t::rm_fd (handle_t handle_)
{
    fd_t index = fd_table [handle_].index;
    assert (index != retired_fd);

    //  Mark the fd as unused.
    pollset [index].fd = retired_fd;
    fd_table [handle_].index = retired_fd;
    retired = true;

    //  Decrease the load metric of the thread.
    load.sub (1);
}

void zmq::poll_t::set_pollin (handle_t handle_)
{
    int index = fd_table [handle_].index;
    pollset [index].events |= POLLIN;
}

void zmq::poll_t::reset_pollin (handle_t handle_)
{
    int index = fd_table [handle_].index;
    pollset [index].events &= ~((short) POLLIN);
}

void zmq::poll_t::set_pollout (handle_t handle_)
{
    int index = fd_table [handle_].index;
    pollset [index].events |= POLLOUT;
}

void zmq::poll_t::reset_pollout (handle_t handle_)
{
    int index = fd_table [handle_].index;
    pollset [index].events &= ~((short) POLLOUT);
}

void zmq::poll_t::add_timer (i_poll_events *events_)
{
     timers.push_back (events_);
}

void zmq::poll_t::cancel_timer (i_poll_events *events_)
{
    timers_t::iterator it = std::find (timers.begin (), timers.end (), events_);
    if (it != timers.end ())
        timers.erase (it);
}

int zmq::poll_t::get_load ()
{
    return load.get ();
}

void zmq::poll_t::start ()
{
    worker.start (worker_routine, this);
}

void zmq::poll_t::stop ()
{
    stopping = true;
}

void zmq::poll_t::loop ()
{
    while (!stopping) {

        //  Wait for events.
        int rc = poll (&pollset [0], pollset.size (),
            timers.empty () ? -1 : max_timer_period);
        if (rc == -1 && errno == EINTR)
            continue;
        errno_assert (rc != -1);

        //  Handle timer.
        if (!rc) {

            //  Use local list of timers as timer handlers may fill new timers
            //  into the original array.
            timers_t t;
            std::swap (timers, t);

            //  Trigger all the timers.
            for (timers_t::iterator it = t.begin (); it != t.end (); it ++)
                (*it)->timer_event ();

            continue;
        }

        for (pollset_t::iterator it = pollset.begin ();
                it != pollset.end (); it ++) {

            zmq_assert (!(it->revents & POLLNVAL));
            if (it->fd == retired_fd)
               continue;
            if (it->revents & (POLLERR | POLLHUP))
                fd_table [it->fd].events->in_event ();
            if (it->fd == retired_fd)
               continue;
            if (it->revents & POLLOUT)
                fd_table [it->fd].events->out_event ();
            if (it->fd == retired_fd)
               continue;
            if (it->revents & POLLIN)
                fd_table [it->fd].events->in_event ();
        }

        //  Clean up the pollset and update the fd_table accordingly.
        if (retired) {
            pollset_t::size_type i = 0;
            while (i < pollset.size ()) {
                if (pollset [i].fd == retired_fd)
                    pollset.erase (pollset.begin () + i);
                else {
                    fd_table [pollset [i].fd].index = i;
                    i ++;
                }
            }
            retired = false;
        }
    }
}

void zmq::poll_t::worker_routine (void *arg_)
{
    ((poll_t*) arg_)->loop ();
}

#endif
