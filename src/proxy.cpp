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
#include <memory>

#if defined ZMQ_POLL_BASED_ON_POLL && !defined ZMQ_HAVE_WINDOWS && !defined ZMQ_HAVE_AIX
#include <poll.h>
#endif

// These headers end up pulling in zmq.h somewhere in their include
// dependency chain
#include "socket_base.hpp"
#include "socket_poller.hpp"
#include "err.hpp"


// Macros for repetitive code.

// PROXY_CLEANUP() must not be used before these variables are initialized.
#define PROXY_CLEANUP()\
    delete poller_all;\
    delete poller_in;\
    delete poller_control;\
    delete poller_receive_blocked;\
    delete poller_send_blocked;\
    delete poller_both_blocked;\


#define CHECK_RC_EXIT_ON_FAILURE()\
    if (rc < 0) {\
        PROXY_CLEANUP();\
        return close_and_return (&msg, -1);\
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

    // The algorithm below assumes ratio of requests and replies processed
    // under full load to be 1:1.

    int more;
    size_t moresz = sizeof (more);

    // Proxy can be in these three states
    enum {
        active,
        paused,
        terminated
    } state = active;

    zmq::socket_poller_t::event_t events [3];

    // Don't allocate these pollers from stack because they will take more than 900 kB of stack!
    // On Windows this blows up default stack of 1 MB and aborts the program.
    // I wanted to use std::shared_ptr here as the best solution but that requires C++11...
    zmq::socket_poller_t *poller_all             = new (std::nothrow) zmq::socket_poller_t;   // Poll for everything.
    zmq::socket_poller_t *poller_in              = new (std::nothrow) zmq::socket_poller_t;   // Poll only 'ZMQ_POLLIN' on all sockets. Initial blocking poll in loop.
    zmq::socket_poller_t *poller_control         = new (std::nothrow) zmq::socket_poller_t;   // Poll only for 'ZMQ_POLLIN' on 'control_', when proxy is paused.
    zmq::socket_poller_t *poller_receive_blocked = new (std::nothrow) zmq::socket_poller_t;   // All except 'ZMQ_POLLIN' on 'frontend_'.
    zmq::socket_poller_t *poller_send_blocked    = new (std::nothrow) zmq::socket_poller_t;   // All except 'ZMQ_POLLIN' on 'backend_'.
    zmq::socket_poller_t *poller_both_blocked    = new (std::nothrow) zmq::socket_poller_t;   // All except 'ZMQ_POLLIN' on both 'frontend_' and 'backend_'.

    if (poller_all == NULL || poller_in == NULL || poller_control == NULL
        || poller_receive_blocked == NULL || poller_send_blocked == NULL
        || poller_both_blocked == NULL) {
        PROXY_CLEANUP();
        return close_and_return (&msg, -1);
    }

    zmq::socket_poller_t *poller_wait = poller_in;   // Poller for blocking wait, initially all 'ZMQ_POLLIN'.
    bool frontend_equal_to_backend;
    bool frontend_in  = false;
    bool frontend_out = false;
    bool backend_in   = false;
    bool backend_out  = false;
    bool control_in   = false;

    // Register 'frontend_' and 'backend_' with pollers.
    rc = poller_all->add (frontend_, NULL, ZMQ_POLLIN | ZMQ_POLLOUT);
    CHECK_RC_EXIT_ON_FAILURE();
    rc = poller_in->add (frontend_, NULL, ZMQ_POLLIN);   // All 'ZMQ_POLLIN's.
    CHECK_RC_EXIT_ON_FAILURE();
    rc = poller_both_blocked->add (frontend_, NULL, ZMQ_POLLOUT); // Waiting only for 'ZMQ_POLLOUT'.
    CHECK_RC_EXIT_ON_FAILURE();

    if (frontend_ != backend_) {
        rc = poller_all->add (backend_, NULL, ZMQ_POLLIN | ZMQ_POLLOUT);
        CHECK_RC_EXIT_ON_FAILURE();
        rc = poller_in->add (backend_, NULL, ZMQ_POLLIN);   // All 'ZMQ_POLLIN's.
        CHECK_RC_EXIT_ON_FAILURE();
        rc = poller_both_blocked->add (backend_, NULL, ZMQ_POLLOUT);
        CHECK_RC_EXIT_ON_FAILURE();
        rc = poller_send_blocked->add (backend_, NULL, ZMQ_POLLOUT);  // All except 'ZMQ_POLLIN' on 'backend_'.
        CHECK_RC_EXIT_ON_FAILURE();
        rc = poller_send_blocked->add (frontend_, NULL, ZMQ_POLLIN | ZMQ_POLLOUT);  // All except 'ZMQ_POLLIN' on 'backend_'.
        CHECK_RC_EXIT_ON_FAILURE();
        rc = poller_receive_blocked->add (frontend_, NULL, ZMQ_POLLOUT);   // All except 'ZMQ_POLLIN' on 'frontend_'.
        CHECK_RC_EXIT_ON_FAILURE();
        rc = poller_receive_blocked->add (backend_, NULL, ZMQ_POLLIN | ZMQ_POLLOUT);   // All except 'ZMQ_POLLIN' on 'frontend_'.
        CHECK_RC_EXIT_ON_FAILURE();
        frontend_equal_to_backend = false;
    }
    else {
      // If frontend_==backend_ 'poller_send_blocked' and 'poller_receive_blocked' are the same, 'ZMQ_POLLIN' is ignored.
        rc = poller_send_blocked->add (frontend_, NULL, ZMQ_POLLOUT);
        CHECK_RC_EXIT_ON_FAILURE();
        rc = poller_receive_blocked->add (frontend_, NULL, ZMQ_POLLOUT);
        CHECK_RC_EXIT_ON_FAILURE();
        frontend_equal_to_backend = true;
    };


    // Register 'control_' with pollers.
    if (control_ != NULL) {
        rc = poller_all->add (control_, NULL, ZMQ_POLLIN);
        CHECK_RC_EXIT_ON_FAILURE();
        rc = poller_in->add (control_, NULL, ZMQ_POLLIN);
        CHECK_RC_EXIT_ON_FAILURE();
        rc = poller_control->add (control_, NULL, ZMQ_POLLIN);  // When proxy is paused we wait only for ZMQ_POLLIN on 'control_' socket.
        CHECK_RC_EXIT_ON_FAILURE();
        rc = poller_send_blocked->add (control_, NULL, ZMQ_POLLIN);
        CHECK_RC_EXIT_ON_FAILURE();
        rc = poller_receive_blocked->add (control_, NULL, ZMQ_POLLIN);
        CHECK_RC_EXIT_ON_FAILURE();
        rc = poller_both_blocked->add (control_, NULL, ZMQ_POLLIN);
        CHECK_RC_EXIT_ON_FAILURE();
    }


    int i;
    bool request_processed, reply_processed;


    while (state != terminated) {

        // Blocking wait initially only for 'ZMQ_POLLIN' - 'poller_wait' points to 'poller_in'.
        // If one of receiving end's queue is full ('ZMQ_POLLOUT' not available),
        // 'poller_wait' is pointed to 'poller_receive_blocked', 'poller_send_blocked' or 'poller_both_blocked'.
        rc = poller_wait->wait (events, 3, -1);
        if (rc < 0 && errno == ETIMEDOUT)
            rc = 0;
        CHECK_RC_EXIT_ON_FAILURE();

        // Some of events waited for by 'poller_wait' have arrived, now poll for everything without blocking.
        rc = poller_all->wait (events, 3, 0);
        if (rc < 0 && errno == ETIMEDOUT)
            rc = 0;
        CHECK_RC_EXIT_ON_FAILURE();

        for (i = 0; i < rc; i++) {
            if (events [i].socket == frontend_) {
                frontend_in  = (events [i].events & ZMQ_POLLIN ) != 0;
                frontend_out = (events [i].events & ZMQ_POLLOUT) != 0;
            }
            else
            if (events [i].socket == backend_) {
                backend_in   = (events [i].events & ZMQ_POLLIN ) != 0;
                backend_out  = (events [i].events & ZMQ_POLLOUT) != 0;
            }
            else
            if (events [i].socket == control_)
                control_in   = (events [i].events & ZMQ_POLLIN ) != 0;
        }


        //  Process a control command if any.
        if (control_in) {
            rc = control_->recv (&msg, 0);
            CHECK_RC_EXIT_ON_FAILURE();
            rc = control_->getsockopt (ZMQ_RCVMORE, &more, &moresz);
            if (unlikely (rc < 0) || more) {
                PROXY_CLEANUP();
                return close_and_return (&msg, -1);
            }

            //  Copy message to capture socket if any
            rc = capture (capture_, msg);
            CHECK_RC_EXIT_ON_FAILURE();

            if (msg.size () == 5 && memcmp (msg.data (), "PAUSE", 5) == 0) {
                state = paused;
                poller_wait = poller_control;
            }
            else
            if (msg.size () == 6 && memcmp (msg.data (), "RESUME", 6) == 0) {
                state = active;
                poller_wait = poller_in;
            }
            else
            if (msg.size () == 9 && memcmp (msg.data (), "TERMINATE", 9) == 0)
                state = terminated;
            else {
                //  This is an API error, we assert
                puts ("E: invalid command sent to proxy");
                zmq_assert (false);
            }
            control_in = false;
        }

        if (state == active) {

            // Process a request, 'ZMQ_POLLIN' on 'frontend_' and 'ZMQ_POLLOUT' on 'backend_'.
            if (frontend_in && backend_out) {
                rc = forward (frontend_, backend_, capture_, msg);
                CHECK_RC_EXIT_ON_FAILURE();
                request_processed = true;
                frontend_in = backend_out = false;
            }
            else request_processed = false;

            // Process a reply, 'ZMQ_POLLIN' on 'backend_' and 'ZMQ_POLLOUT' on 'frontend_'.
            // If 'frontend_' and 'backend_' are the same this is skipped because previous processing 
            // covers all of the cases.
            if (backend_in && frontend_out && !frontend_equal_to_backend) {
                rc = forward (backend_, frontend_, capture_, msg);
                CHECK_RC_EXIT_ON_FAILURE();
                reply_processed = true;
                backend_in = frontend_out = false;
            }
            else reply_processed = false;

            if (request_processed || reply_processed) {
              // If request/reply is processed that means we had at least one 'ZMQ_POLLOUT' event.
              // Enable corresponding 'ZMQ_POLLIN' if any was disabled.
                if (poller_wait != poller_in) {
                    if (request_processed) {   // 'frontend_' -> 'backend_'
                        if (poller_wait == poller_both_blocked)
                            poller_wait = poller_send_blocked;
                        else
                        if (poller_wait == poller_receive_blocked)
                            poller_wait = poller_in;
                    }
                    if (reply_processed) {   // 'backend_' -> 'frontend_'
                        if (poller_wait == poller_both_blocked)
                            poller_wait = poller_receive_blocked;
                        else
                        if (poller_wait == poller_send_blocked)
                            poller_wait = poller_in;
                    }
                }
            }
            else {
              // No requests have been processed, there were no 'ZMQ_POLLOUT' events.
              // That means that receiving end queue(s) is/are full.
              // Disable receiving 'ZMQ_POLLIN' for sockets for which there's no 'ZMQ_POLLOUT'.
                if (frontend_in) {
                    if (poller_wait == poller_send_blocked)
                        poller_wait = poller_both_blocked;
                    else
                        poller_wait = poller_receive_blocked;
                }
                if (backend_in && !frontend_equal_to_backend) {
                    if (poller_wait == poller_receive_blocked)
                        poller_wait = poller_both_blocked;
                    else
                        poller_wait = poller_send_blocked;
                }
            }

        }
    }
    PROXY_CLEANUP();
    return close_and_return (&msg, 0);
}

