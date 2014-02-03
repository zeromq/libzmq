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

#if defined(thread_local)
#define STATIC4TLS_OR_NA static thread_local
#else
#define STATIC4TLS_OR_NA
#endif

int
zmq::proxy (
        class socket_base_t **open_endpoint_,
        class socket_base_t **frontend_,
        class socket_base_t **backend_,
        class socket_base_t *capture_,
        class socket_base_t *control_,
        zmq::proxy_hook_t **hook_,
        long time_out_)
{
    // all threads statics
    static zmq_pollitem_t null_item = { NULL, 0, ZMQ_POLLIN, 0 };
    static zmq::proxy_hook_t dummy_hook = {NULL, NULL, NULL};
    static zmq::proxy_hook_t* no_hooks[ZMQ_PROXY_CHAIN_MAX_LENGTH];

    // local thread statics or not static if LTS is not available (LTS is only required for zmq_proxy_open_chain
    STATIC4TLS_OR_NA bool is_initialised = false;
    STATIC4TLS_OR_NA msg_t msg;
    STATIC4TLS_OR_NA int rc;
    STATIC4TLS_OR_NA int more;
    STATIC4TLS_OR_NA size_t moresz;
    STATIC4TLS_OR_NA size_t qt_pairs_fb; // number of pair of sockets: both arrays frontend_ & backend_ ends with NULL
    STATIC4TLS_OR_NA zmq_pollitem_t items [2 * ZMQ_PROXY_CHAIN_MAX_LENGTH + 1]; // +1 for the control socket
    STATIC4TLS_OR_NA int linked_to [2 * ZMQ_PROXY_CHAIN_MAX_LENGTH + 1];
    STATIC4TLS_OR_NA hook_f hook_func [2 * ZMQ_PROXY_CHAIN_MAX_LENGTH + 1];
    STATIC4TLS_OR_NA void* hook_data [2 * ZMQ_PROXY_CHAIN_MAX_LENGTH + 1];
    STATIC4TLS_OR_NA int qt_poll_items;
    STATIC4TLS_OR_NA int qt_sockets;
    STATIC4TLS_OR_NA enum {
        active,
        paused,
        terminated
    } state; //  Proxy can be in these three states
    STATIC4TLS_OR_NA zmq::proxy_hook_t **hook;

    if (!open_endpoint_ && !frontend_ && !backend_ && !capture_ && !control_ && !hook_ && !time_out_) {
        is_initialised = false; // hawful hack to force proxy reinitialisation
        return 0;
    }
    if (!is_initialised || time_out_ == -1) { // if we wait on poll, then the proxy has no memory => we reinitialize everything
        if (!msg.check()) {
            rc = msg.init ();
            if (rc != 0)
                return -1;
        }

        //  The algorithm below assumes ratio of requests and replies processed
        //  under full load to be 1:1.

        // counts the number of pair of sockets in frontend_/backend_
        for (qt_pairs_fb = 0; qt_pairs_fb < 2 * ZMQ_PROXY_CHAIN_MAX_LENGTH ; qt_pairs_fb++) // "2 *" is to be sure to assert later
            if (!frontend_[qt_pairs_fb] && !backend_[qt_pairs_fb])
                break;

        // strick criteria for zmq_proxy, zmq_proxy_steerable, zmq_proxy_hook: one single proxy with frontend and backend defined
        if (time_out_ == -1)
            if (!frontend_[0] || !backend_[0]) {
                errno = EFAULT;
                return -1;
            }

        hook = hook_ ? hook_ : no_hooks;

        // fill the zmq_pollitem_t array, identifying with linked_to if a socket is alone (open) or to which one it is proxied
        int k = 0;
        if (open_endpoint_)
            while (open_endpoint_[k]) {
                zmq_assert(k < ZMQ_PROXY_CHAIN_MAX_LENGTH); // avoid dynamic allocation as we have no guarranty to reach the deallocator => limit the chain length
                memcpy(&items[k], &null_item, sizeof(null_item));
                items[k].socket = open_endpoint_[k];
                linked_to[k] = k; // this socket is alone (open)
                hook_func[k] = NULL; // No hook will be executed on an end-point socket since we don't recv the messages
                k++;
            }
        for (size_t i = 0; i < qt_pairs_fb; i++, k++) {
            zmq_assert(k < ZMQ_PROXY_CHAIN_MAX_LENGTH); // avoid dynamic allocation as we have no guarranty to reach the deallocator => limit the chain length
            if (hook_) { // TODO: utiliser plutôt hook
                if (!hook_[i]) // Check if a hook is used (hooks are only for proxies defined with pairs of sockets in frontend_ & backend_)
                    hook_[i] = &dummy_hook;
            }
            else
                no_hooks[i] = &dummy_hook;
            memcpy(&items[k], &null_item, sizeof(null_item));
            hook_data[k] = hook[i]->data;
            if (!frontend_[i]) {
                items[k].socket = backend_[i];
                linked_to[k] = k; // this socket is alone (open)
                hook_func[k] = NULL; // No hook will be executed on an "open" socket since we don't recv the messages
            }
            else if (!backend_[i]) {
                items[k].socket = frontend_[i];
                linked_to[k] = k; // this socket is alone (open)
                hook_func[k] = NULL; // No hook will be executed on an "open" socket since we don't recv the messages
            }
            else {
                items[k].socket = frontend_[i];
                linked_to[k] = k+1; // this socket is proxied to the next one
                hook_func[k] = hook[i]->front2back_hook;
                k++;
                hook_data[k] = hook[i]->data;
                memcpy(&items[k], &null_item, sizeof(null_item));
                items[k].socket = backend_[i];
                linked_to[k] = k-1; // this socket is proxied to the previous one
                hook_func[k] = hook[i]->back2front_hook;
            }
        }
        if (!k) { // we require at least one socket
            errno = EFAULT;
            return -1;
        }
        memcpy(&items[k], &null_item, sizeof(null_item));
        items[k].socket =     control_;
        qt_poll_items = (control_ ? k + 1 : k);
        qt_sockets = k;

        state = active;
        is_initialised = true;
    }

    while (state != terminated) {
        //  Wait while there are either requests or replies to process.
        rc = zmq_poll (&items [0], qt_poll_items, time_out_);
        if (unlikely (rc < 0))
            return -1;
        if (rc == 0) // no message. Obviously, we are in the case where: time_out_ != -1
            return 0;

        //  Process a control command if any
        if (control_ && items [qt_poll_items - 1].revents & ZMQ_POLLIN) {
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
        for (int i = 0; i < qt_sockets; i++) {
            if (state == active
            &&  items [i].revents & ZMQ_POLLIN) {
                if (i != linked_to[i]) { // this socket is proxied to the linked_to[i] one
                    rc = forward((zmq::socket_base_t *) items[i].socket,
                                 (zmq::socket_base_t *) items[linked_to[i]].socket,
                                 (zmq::socket_base_t *) capture_,
                                 msg,
                                 hook_func[i],
                                 hook_data[i]);
                    if (unlikely (rc < 0))
                        return -1;
                }
                else // this socket is alone (open)
                    return time_out_ == -1 ? 1 : i + 1; // 1 is for backward compatibility, sockets are counted starting at 1
            }
        }

        // proxy opening
        if (time_out_ != -1)
            break;
    }
    return 0;
}
