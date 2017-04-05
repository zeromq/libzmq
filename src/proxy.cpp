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

//  On AIX platform, poll.h has to be included first to get consistent
//  definition of pollfd structure (AIX uses 'reqevents' and 'retnevents'
//  instead of 'events' and 'revents' and defines macros to map from POSIX-y
//  names to AIX-specific names).
//  zmq.h must be included *after* poll.h for AIX to build properly.
//  precompiled.hpp includes include/zmq.h
#if defined ZMQ_POLL_BASED_ON_POLL && defined ZMQ_HAVE_AIX
#include <poll.h>
#endif

#include "precompiled.hpp"
#include <stddef.h>
#include "poller.hpp"
#include "proxy.hpp"
#include "likely.hpp"

#if defined ZMQ_POLL_BASED_ON_POLL && !defined ZMQ_HAVE_WINDOWS && !defined ZMQ_HAVE_AIX
#include <poll.h>
#endif

// These headers end up pulling in zmq.h somewhere in their include
// dependency chain
#include "socket_base.hpp"
#include "socket_poller.hpp"
#include "err.hpp"




// sleep_ms () copied from signaller.cpp.
// Helper to sleep for specific number of milliseconds (or until signal)
//
static int sleep_ms (unsigned int ms_)
{
    if (ms_ == 0)
        return 0;
#if defined ZMQ_HAVE_WINDOWS
    Sleep (ms_ > 0 ? ms_ : INFINITE);
    return 0;
#elif defined ZMQ_HAVE_ANDROID
    usleep (ms_ * 1000);
    return 0;
#else
    return usleep (ms_ * 1000);
#endif
}



int capture (
    class zmq::socket_base_t *capture_,
    zmq::msg_t& msg_,
    int more_ = 0)
{
    //  Copy message to capture socket if any
    if (capture_) {
        zmq::msg_t ctrl;
        int rc = ctrl.init ();
        if (unlikely (rc < 0))
            return -1;
        rc = ctrl.copy (msg_);
        if (unlikely (rc < 0))
            return -1;
        rc = capture_->send (&ctrl, more_ ? ZMQ_SNDMORE : 0);
        if (unlikely (rc < 0))
            return -1;
    }
    return 0;
}



int forward (
    class zmq::socket_base_t *from_,
    class zmq::socket_base_t *to_,
    class zmq::socket_base_t *capture_,
    zmq::msg_t& msg_)
{
    int more;
    size_t moresz;
    while (true) {
        int rc = from_->recv (&msg_, 0);
        if (unlikely (rc < 0))
            return -1;

        moresz = sizeof more;
        rc = from_->getsockopt (ZMQ_RCVMORE, &more, &moresz);
        if (unlikely (rc < 0))
            return -1;

        //  Copy message to capture socket if any
        rc = capture (capture_, msg_, more);
        if (unlikely (rc < 0))
            return -1;

        rc = to_->send (&msg_, more ? ZMQ_SNDMORE : 0);
        if (unlikely (rc < 0))
            return -1;
        if (more == 0)
            break;
    }
    return 0;
}



int zmq::proxy (
    class socket_base_t *frontend_,
    class socket_base_t *backend_,
    class socket_base_t *capture_,
    class socket_base_t *control_)
{
    msg_t msg;
    int rc = msg.init ();
    if (rc != 0)
        return -1;

    //  The algorithm below assumes ratio of requests and replies processed
    //  under full load to be 1:1.

    int more;
    size_t moresz = sizeof (more);
    zmq_pollitem_t items_in [] = {
        { frontend_, 0, ZMQ_POLLIN, 0 },
        { backend_,  0, ZMQ_POLLIN, 0 },
        { control_,  0, ZMQ_POLLIN, 0 }
    };
    int qt_poll_items = (control_ ? 3 : 2);
    zmq_pollitem_t items_out [] = {
        { frontend_, 0, ZMQ_POLLOUT, 0 },
        { backend_,  0, ZMQ_POLLOUT, 0 }
    };

    //  Proxy can be in these three states
    enum {
        active,
        paused,
        terminated
    } state = active;

    zmq_poller_event_t events_in [3], events_out [2], event_control;
    zmq::socket_poller_t poller_in, poller_out, poller_control;

    // Register 'items_in' sockets with 'poller_in'.
    // No need for zmq_poller_modify () since all events are ZMQ_POLLIN.
    for (int i = 0; i < qt_poll_items; i++) {
        bool duplicate = false;
        if (items_in [i].socket) {
          //  Poll item is a 0MQ socket.
            for (int j = 0; j < i; ++j) {
              // Check for repeat entries
                if (items_in [j].socket == items_in [i].socket) {
                    duplicate = true;
                    break;
                }
            }
            if (!duplicate) {
                rc = zmq_poller_add (&poller_in, items_in [i].socket, NULL, ZMQ_POLLIN);
                if (rc < 0)
                    return close_and_return (&msg, -1);
            }
        } else {
          //  Poll item is a raw file descriptor.
            for (int j = 0; j < i; ++j) {
              // Check for repeat entries
                if (!items_in [j].socket && items_in [j].fd == items_in [i].fd) {
                    duplicate = true;
                    break;
                }
            }
            if (!duplicate) {
                rc = zmq_poller_add_fd (&poller_in, items_in [i].fd, NULL, ZMQ_POLLIN);
                if (rc < 0)
                    return close_and_return (&msg, -1);
            }
        }
    }

    //  Register 'items_out' sockets with 'poller_out'.
    // No need for zmq_poller_modify () since all events are ZMQ_POLLOUT.
    for (int i = 0; i < 2; i++) {
        bool duplicate = false;
        if (items_out [i].socket) {  //  Poll item is a 0MQ socket.
          // Check for repeat entries.
            for (int j = 0; j < i; ++j) {
                if (items_out [j].socket == items_out [i].socket) {
                    duplicate = true;
                    break;
                }
            }
            if (!duplicate) {
                rc = zmq_poller_add (&poller_out, items_out [i].socket, NULL, ZMQ_POLLOUT);
                if (rc < 0)
                    return close_and_return (&msg, -1);
            }
        } else {  //  Poll item is a raw file descriptor.
          // Check for repeat entries.
            for (int j = 0; j < i; ++j) {
                if (!items_out [j].socket && items_out [j].fd == items_out [i].fd) {
                    duplicate = true;
                    break;
                }
            }
            if (!duplicate) {
                rc = zmq_poller_add_fd (&poller_out, items_out [i].fd, NULL, ZMQ_POLLOUT);
                if (rc < 0)
                    return close_and_return (&msg, -1);
            }
        }
    }

    if (control_) {
      // Register 'control_' socket with 'poller_control'.
      // When proxy is paused we wait only for ZMQ_POLLIN on 'control_' socket.
        rc = zmq_poller_add (&poller_control, control_, NULL, ZMQ_POLLIN);
        if (rc < 0)
            return close_and_return (&msg, -1);
    }


    int i, j;

    while (state != terminated) {

        // If proxy is paused we don't care about anything except control_ ZMQ_POLLIN messages.
        // We wait for either "RESUME" or "TERMINATE".
        if (state == paused) {
            rc = poller_control.wait( (zmq::socket_poller_t::event_t *)&event_control, 1, -1);
            if (unlikely (rc < 0))
                return close_and_return (&msg, -1);
        } else {
          //  Wait while there are either requests or replies to process.
            rc = poller_in.wait( (zmq::socket_poller_t::event_t *)&events_in [0], qt_poll_items, -1);
            if (unlikely (rc < 0))
                return close_and_return (&msg, -1);

              // Transform 'poller_in' events into zmq_pollitem events.
              // 'items_in' contains all items, while 'events_in' only contains fired events.
              // If there are some duplicate items (frontend_==backend_) in 'items_in' all of them are marked as signalled.
            for (i = 0; i < qt_poll_items; i++) {
                for (j = 0; j < qt_poll_items; j++) {
                    if (
                        (items_in [i].socket && items_in [i].socket == events_in [j].socket) ||
                        (! (items_in [i].socket || events_in [j].socket) && items_in [i].fd == events_in [j].fd)
                        ) {
                        if (events_in [j].events)
                            items_in [i].revents = ZMQ_POLLIN;
                    }
                }
            }

            //  Get the pollout separately because when combining this with pollin it maxes the CPU
            //  because pollout shall most of the time return directly.
            //  POLLOUT is only checked when frontend and backend sockets are not the same.
            if (frontend_ != backend_) {
                rc = poller_out.wait( (zmq::socket_poller_t::event_t *)&events_out [0], 2, 0);
                if (unlikely (rc < 0)) {
                    return close_and_return (&msg, -1);
                }

                // Transform 'poller_out' events into zmq_pollitem events.
                // 'items_out' contains all items, while 'events_out' only contains fired events.
                // If there are some duplicate items (frontend_==backend_) in 'items_out' all of them are marked as signalled.
                for (i = 0; i < 2; i++) {
                    for (j = 0; j < 2; j++) {
                        if (
                            (items_out [i].socket && items_out [i].socket == events_out [j].socket) ||
                            (! (items_out [i].socket || events_out [j].socket) && items_out [i].fd == events_out [j].fd)
                            ) {
                            if (events_out [j].events)
                                items_out [i].revents = ZMQ_POLLOUT;
                        }
                    }
                }
            }
        }

        //  Process a control command if any
        if (control_) {
            if ( (state == active && items_in [2].revents != 0) || (state == paused && event_control.events != 0)) {
                rc = control_->recv (&msg, 0);
                if (unlikely (rc < 0))
                    return close_and_return (&msg, -1);
                rc = control_->getsockopt (ZMQ_RCVMORE, &more, &moresz);
                if (unlikely (rc < 0) || more)
                    return close_and_return (&msg, -1);

                //  Copy message to capture socket if any
                rc = capture (capture_, msg);
                if (unlikely (rc < 0))
                    return close_and_return (&msg, -1);

                if (msg.size () == 5 && memcmp(msg.data (), "PAUSE", 5) == 0)
                    state = paused;
                else
                if (msg.size () == 6 && memcmp(msg.data (), "RESUME", 6) == 0)
                    state = active;
                else
                if (msg.size () == 9 && memcmp(msg.data (), "TERMINATE", 9) == 0)
                    state = terminated;
                else {
                    //  This is an API error, we assert
                    puts ("E: invalid command sent to proxy");
                    zmq_assert (false);
                }
                items_in [2].revents = 0;
            }
        }

        if (state == active) {

            //  Process a request.
            if (items_in [0].revents
               && (frontend_ == backend_ || items_out [1].revents != 0)) {
                rc = forward (frontend_, backend_, capture_, msg);
                if (unlikely (rc < 0))
                    return close_and_return (&msg, -1);
                items_in [0].revents = items_out [1].revents = 0;
            }

            //  Process a reply.
            if (frontend_ != backend_
               &&  items_in [1].revents != 0
               && items_out [0].revents != 0) {
                rc = forward (backend_, frontend_, capture_, msg);
                if (unlikely (rc < 0))
                    return close_and_return (&msg, -1);
                items_in [1].revents = items_out [0].revents = 0;
            }

            // If 'frontend_' is signalled with both 'ZMQ_POLLIN' and 'ZMQ_POLLOUT' and 'ZMQ_POLLOUT' is
            // not available for 'backend_', we need to make pause. Otherwise we will get a 100% CPU loop.
            // The same stands for 'backend_' signalled with both 'ZMQ_POLLIN' and 'ZMQ_POLLOUT' without
            // 'frontend_' signalled with 'ZMQ_POLLOUT'.
            // This is generally highly irregular situation but this is just to prevent eating up CPU.
            if (frontend_ != backend_
               && ( (items_in [0].revents != 0 && items_out [0].revents != 0)
                   || (items_in [1].revents != 0 && items_out [1].revents != 0))) {
                sleep_ms (10);
            }

        }
    }
    return close_and_return (&msg, 0);
}


