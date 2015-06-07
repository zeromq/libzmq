/*
    Copyright (c) 2007-2015 Contributors as noted in the AUTHORS file

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

#include <stddef.h>
#include "poller.hpp"
#include "proxy.hpp"
#include "likely.hpp"

//  On AIX platform, poll.h has to be included first to get consistent
//  definition of pollfd structure (AIX uses 'reqevents' and 'retnevents'
//  instead of 'events' and 'revents' and defines macros to map from POSIX-y
//  names to AIX-specific names).
#if defined ZMQ_POLL_BASED_ON_POLL
#include <poll.h>
#endif

// These headers end up pulling in zmq.h somewhere in their include
// dependency chain
#include "socket_base.hpp"
#include "err.hpp"

// zmq.h must be included *after* poll.h for AIX to build properly
#include "../include/zmq.h"

int capture(
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
        rc = capture_->send (&ctrl, more_? ZMQ_SNDMORE: 0);
        if (unlikely (rc < 0))
            return -1;
    }
    return 0;
}

int forward(
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
        rc = capture(capture_, msg_, more);
        if (unlikely (rc < 0))
            return -1;

        rc = to_->send (&msg_, more? ZMQ_SNDMORE: 0);
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
    size_t moresz;
    zmq_pollitem_t items [] = {
        { frontend_, 0, ZMQ_POLLIN, 0 },
        { backend_, 0, ZMQ_POLLIN, 0 },
        { control_, 0, ZMQ_POLLIN, 0 }
    };
    int qt_poll_items = (control_ ? 3 : 2);
    zmq_pollitem_t itemsout [] = {
        { frontend_, 0, ZMQ_POLLOUT, 0 },
        { backend_, 0, ZMQ_POLLOUT, 0 }
    };

    //  Proxy can be in these three states
    enum {
        active,
        paused,
        terminated
    } state = active;

    while (state != terminated) {
        //  Wait while there are either requests or replies to process.
        rc = zmq_poll (&items [0], qt_poll_items, -1);
        if (unlikely (rc < 0))
            return -1;

        //  Get the pollout separately because when combining this with pollin it maxes the CPU
        //  because pollout shall most of the time return directly.
        //  POLLOUT is only checked when frontend and backend sockets are not the same.
        if (frontend_ != backend_) {
            rc = zmq_poll (&itemsout [0], 2, 0);
            if (unlikely (rc < 0)) {
                return -1;
            }
        }

        //  Process a control command if any
        if (control_ && items [2].revents & ZMQ_POLLIN) {
            rc = control_->recv (&msg, 0);
            if (unlikely (rc < 0))
                return -1;

            moresz = sizeof more;
            rc = control_->getsockopt (ZMQ_RCVMORE, &more, &moresz);
            if (unlikely (rc < 0) || more)
                return -1;

            //  Copy message to capture socket if any
            rc = capture(capture_, msg);
            if (unlikely (rc < 0))
                return -1;

            if (msg.size () == 5 && memcmp (msg.data (), "PAUSE", 5) == 0)
                state = paused;
            else
            if (msg.size () == 6 && memcmp (msg.data (), "RESUME", 6) == 0)
                state = active;
            else
            if (msg.size () == 9 && memcmp (msg.data (), "TERMINATE", 9) == 0)
                state = terminated;
            else {
                //  This is an API error, we should assert
                puts ("E: invalid command sent to proxy");
                zmq_assert (false);
            }
        }
        //  Process a request
        if (state == active
        &&  items [0].revents & ZMQ_POLLIN
        &&  (frontend_ == backend_ || itemsout [1].revents & ZMQ_POLLOUT)) {
            rc = forward(frontend_, backend_, capture_,msg);
            if (unlikely (rc < 0))
                return -1;
        }
        //  Process a reply
        if (state == active
        &&  frontend_ != backend_
        &&  items [1].revents & ZMQ_POLLIN
        &&  itemsout [0].revents & ZMQ_POLLOUT) {
            rc = forward(backend_, frontend_, capture_,msg);
            if (unlikely (rc < 0))
                return -1;
        }
    }
    return 0;
}
