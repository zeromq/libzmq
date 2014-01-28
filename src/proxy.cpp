/*
    Copyright (c) 2007-2014 Contributors as noted in the AUTHORS file

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stddef.h>
#include "platform.hpp"
#include "proxy.hpp"
#include "likely.hpp"

#if defined ZMQ_FORCE_SELECT
#define ZMQ_POLL_BASED_ON_SELECT
#elif defined ZMQ_FORCE_POLL
#define ZMQ_POLL_BASED_ON_POLL
#elif defined ZMQ_HAVE_LINUX || defined ZMQ_HAVE_FREEBSD ||\
    defined ZMQ_HAVE_OPENBSD || defined ZMQ_HAVE_SOLARIS ||\
    defined ZMQ_HAVE_OSX || defined ZMQ_HAVE_QNXNTO ||\
    defined ZMQ_HAVE_HPUX || defined ZMQ_HAVE_AIX ||\
    defined ZMQ_HAVE_NETBSD
#define ZMQ_POLL_BASED_ON_POLL
#elif defined ZMQ_HAVE_WINDOWS || defined ZMQ_HAVE_OPENVMS ||\
     defined ZMQ_HAVE_CYGWIN
#define ZMQ_POLL_BASED_ON_SELECT
#endif

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

int
capture(
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

int
forward(
        class zmq::socket_base_t *from_,
        class zmq::socket_base_t *to_,
        class zmq::socket_base_t *capture_,
        zmq::msg_t& msg_,
        zmq::hook_f do_hook_,
        void *data_)
{
    int more;
    size_t moresz;
    for (size_t n = 1;; n++) {
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

        // Hook
        if (do_hook_) {
            rc = (*do_hook_)(from_, to_, capture_, &msg_, more ? n : 0, data_); // first message: n == 1, mth message: n == m, last message: n == 0
            if (unlikely (rc < 0))
                return -1;
        }

        rc = to_->send (&msg_, more? ZMQ_SNDMORE: 0);
        if (unlikely (rc < 0))
            return -1;
        if (more == 0)
            break;
    }
    return 0;
}

int
zmq::proxy (
        class socket_base_t **frontend_,
        class socket_base_t **backend_,
        class socket_base_t *capture_,
        class socket_base_t *control_,
        zmq::proxy_hook_t **hook_)
{
    msg_t msg;
    int rc = msg.init ();
    if (rc != 0)
        return -1;

    //  The algorithm below assumes ratio of requests and replies processed
    //  under full load to be 1:1.

    int more;
    size_t moresz;
    size_t n = 0; // number of pair of sockets: the array ends with NULL
    for (;; n++) { // counts the number of pair of sockets
        if (!frontend_[n] && !backend_[n])
            break;
        if (!frontend_[n] || !backend_[n]) {
            errno = EFAULT;
            return -1;
        }
    }
    if (!n) {
        errno = EFAULT;
        return -1;
    }
    // avoid dynamic allocation as we have no guarranty to reach the deallocator => limit the chain length
    zmq_assert(n <= ZMQ_PROXY_CHAIN_MAX_LENGTH);
    zmq_pollitem_t items [2 * ZMQ_PROXY_CHAIN_MAX_LENGTH + 1]; // +1 for the control socket
    static zmq_pollitem_t null_item = { NULL, 0, ZMQ_POLLIN, 0 };
    static zmq::proxy_hook_t dummy_hook = {NULL, NULL, NULL};
    static zmq::proxy_hook_t* no_hooks[ZMQ_PROXY_CHAIN_MAX_LENGTH];
    if (!hook_)
        hook_ = no_hooks;
    else
        for (size_t i = 0; i < n; i++)
            if (!hook_[i]) // Check if a hook is used
                hook_[i] = &dummy_hook;
    for (size_t i = 0; i < n; i++) {
        memcpy(&items[2 * i], &null_item, sizeof(null_item));
        items[2 * i].socket =     frontend_[i];
        memcpy(&items[2 * i + 1], &null_item, sizeof(null_item));
        items[2 * i + 1].socket = backend_[i];
        no_hooks[i] = &dummy_hook;
    }
    memcpy(&items[2 * n], &null_item, sizeof(null_item));
    items[2 * n].socket =     control_;
    int qt_poll_items = (control_ ? 2 * n + 1 : 2 * n);

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

        //  Process a control command if any
        if (control_ && items [2 * n].revents & ZMQ_POLLIN) {
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

        // process each pair of sockets
        for (size_t i = 0; i < n; i++) {
            //  Process a request
            if (state == active
            &&  items [2 * i].revents & ZMQ_POLLIN) {
                rc = forward(frontend_[i], backend_[i], capture_, msg, hook_[i]->front2back_hook, hook_[i]->data);
                if (unlikely (rc < 0))
                    return -1;
            }
            //  Process a reply
            if (state == active
            &&  items [2 * i + 1].revents & ZMQ_POLLIN) {
                rc = forward(backend_[i], frontend_[i], capture_, msg, hook_[i]->back2front_hook, hook_[i]->data);
                if (unlikely (rc < 0))
                    return -1;
            }
        }
    }
    return 0;
}
