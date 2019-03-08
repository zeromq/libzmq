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

#include <stddef.h>
#include "poller.hpp"
#include "proxy.hpp"
#include "likely.hpp"
#include "msg.hpp"

#if defined ZMQ_POLL_BASED_ON_POLL && !defined ZMQ_HAVE_WINDOWS                \
  && !defined ZMQ_HAVE_AIX
#include <poll.h>
#endif

// These headers end up pulling in zmq.h somewhere in their include
// dependency chain
#include "socket_base.hpp"
#include "err.hpp"

#ifdef ZMQ_HAVE_POLLER

#include "socket_poller.hpp"

//  Macros for repetitive code.

//  PROXY_CLEANUP() must not be used before these variables are initialized.
#define PROXY_CLEANUP()                                                        \
    do {                                                                       \
        delete poller_all;                                                     \
        delete poller_in;                                                      \
        delete poller_control;                                                 \
        delete poller_receive_blocked;                                         \
        delete poller_send_blocked;                                            \
        delete poller_both_blocked;                                            \
        delete poller_frontend_only;                                           \
        delete poller_backend_only;                                            \
    } while (false)


#define CHECK_RC_EXIT_ON_FAILURE()                                             \
    do {                                                                       \
        if (rc < 0) {                                                          \
            PROXY_CLEANUP ();                                                  \
            return close_and_return (&msg, -1);                                \
        }                                                                      \
    } while (false)

#endif //  ZMQ_HAVE_POLLER


// Control socket messages

typedef struct
{
    uint64_t msg_in;
    uint64_t bytes_in;
    uint64_t msg_out;
    uint64_t bytes_out;
} zmq_socket_stats_t;


// Utility functions

int capture (class zmq::socket_base_t *capture_,
             zmq::msg_t *msg_,
             int more_ = 0)
{
    //  Copy message to capture socket if any
    if (capture_) {
        zmq::msg_t ctrl;
        int rc = ctrl.init ();
        if (unlikely (rc < 0))
            return -1;
        rc = ctrl.copy (*msg_);
        if (unlikely (rc < 0))
            return -1;
        rc = capture_->send (&ctrl, more_ ? ZMQ_SNDMORE : 0);
        if (unlikely (rc < 0))
            return -1;
    }
    return 0;
}

int forward (class zmq::socket_base_t *from_,
             zmq_socket_stats_t *from_stats_,
             class zmq::socket_base_t *to_,
             zmq_socket_stats_t *to_stats_,
             class zmq::socket_base_t *capture_,
             zmq::msg_t *msg_)
{
    // Forward a burst of messages
    for (unsigned int i = 0; i < zmq::proxy_burst_size; i++) {
        int more;
        size_t moresz;
        size_t complete_msg_size = 0;

        // Forward all the parts of one message
        while (true) {
            int rc = from_->recv (msg_, ZMQ_DONTWAIT);
            if (rc < 0) {
                if (likely (errno == EAGAIN && i > 0))
                    return 0; // End of burst
                else
                    return -1;
            }

            complete_msg_size += msg_->size ();

            moresz = sizeof more;
            rc = from_->getsockopt (ZMQ_RCVMORE, &more, &moresz);
            if (unlikely (rc < 0))
                return -1;

            //  Copy message to capture socket if any
            rc = capture (capture_, msg_, more);
            if (unlikely (rc < 0))
                return -1;

            rc = to_->send (msg_, more ? ZMQ_SNDMORE : 0);
            if (unlikely (rc < 0))
                return -1;

            if (more == 0)
                break;
        }

        // A multipart message counts as 1 packet:
        from_stats_->msg_in++;
        from_stats_->bytes_in += complete_msg_size;
        to_stats_->msg_out++;
        to_stats_->bytes_out += complete_msg_size;
    }

    return 0;
}

static int loop_and_send_multipart_stat (zmq::socket_base_t *control_,
                                         uint64_t stat_,
                                         bool first_,
                                         bool more_)
{
    int rc;
    zmq::msg_t msg;

    //  VSM of 8 bytes can't fail to init
    msg.init_size (sizeof (uint64_t));
    memcpy (msg.data (), &stat_, sizeof (uint64_t));

    //  if the first message is handed to the pipe successfully then the HWM
    //  is not full, which means failures are due to interrupts (on Windows pipes
    //  are TCP sockets), so keep retrying
    do {
        rc = control_->send (&msg, more_ ? ZMQ_SNDMORE : 0);
    } while (!first_ && rc != 0 && errno == EAGAIN);

    return rc;
}

int reply_stats (class zmq::socket_base_t *control_,
                 zmq_socket_stats_t *frontend_stats_,
                 zmq_socket_stats_t *backend_stats_)
{
    // first part: frontend stats - the first send might fail due to HWM
    if (loop_and_send_multipart_stat (control_, frontend_stats_->msg_in, true,
                                      true)
        != 0)
        return -1;

    loop_and_send_multipart_stat (control_, frontend_stats_->bytes_in, false,
                                  true);
    loop_and_send_multipart_stat (control_, frontend_stats_->msg_out, false,
                                  true);
    loop_and_send_multipart_stat (control_, frontend_stats_->bytes_out, false,
                                  true);

    // second part: backend stats
    loop_and_send_multipart_stat (control_, backend_stats_->msg_in, false,
                                  true);
    loop_and_send_multipart_stat (control_, backend_stats_->bytes_in, false,
                                  true);
    loop_and_send_multipart_stat (control_, backend_stats_->msg_out, false,
                                  true);
    loop_and_send_multipart_stat (control_, backend_stats_->bytes_out, false,
                                  false);

    return 0;
}


#ifdef ZMQ_HAVE_POLLER

int zmq::proxy (class socket_base_t *frontend_,
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

    //  Proxy can be in these three states
    enum
    {
        active,
        paused,
        terminated
    } state = active;

    bool frontend_equal_to_backend;
    bool frontend_in = false;
    bool frontend_out = false;
    bool backend_in = false;
    bool backend_out = false;
    bool control_in = false;
    zmq::socket_poller_t::event_t events[3];
    zmq_socket_stats_t frontend_stats;
    zmq_socket_stats_t backend_stats;
    memset (&frontend_stats, 0, sizeof (frontend_stats));
    memset (&backend_stats, 0, sizeof (backend_stats));

    //  Don't allocate these pollers from stack because they will take more than 900 kB of stack!
    //  On Windows this blows up default stack of 1 MB and aborts the program.
    //  I wanted to use std::shared_ptr here as the best solution but that requires C++11...
    zmq::socket_poller_t *poller_all =
      new (std::nothrow) zmq::socket_poller_t; //  Poll for everything.
    zmq::socket_poller_t *poller_in = new (std::nothrow) zmq::
      socket_poller_t; //  Poll only 'ZMQ_POLLIN' on all sockets. Initial blocking poll in loop.
    zmq::socket_poller_t *poller_control = new (std::nothrow) zmq::
      socket_poller_t; //  Poll only for 'ZMQ_POLLIN' on 'control_', when proxy is paused.
    zmq::socket_poller_t *poller_receive_blocked = new (std::nothrow)
      zmq::socket_poller_t; //  All except 'ZMQ_POLLIN' on 'frontend_'.

    //  If frontend_==backend_ 'poller_send_blocked' and 'poller_receive_blocked' are the same, 'ZMQ_POLLIN' is ignored.
    //  In that case 'poller_send_blocked' is not used. We need only 'poller_receive_blocked'.
    //  We also don't need 'poller_both_blocked', 'poller_backend_only' nor 'poller_frontend_only' no need to initialize it.
    //  We save some RAM and time for initialization.
    zmq::socket_poller_t *poller_send_blocked =
      NULL; //  All except 'ZMQ_POLLIN' on 'backend_'.
    zmq::socket_poller_t *poller_both_blocked =
      NULL; //  All except 'ZMQ_POLLIN' on both 'frontend_' and 'backend_'.
    zmq::socket_poller_t *poller_frontend_only =
      NULL; //  Only 'ZMQ_POLLIN' and 'ZMQ_POLLOUT' on 'frontend_'.
    zmq::socket_poller_t *poller_backend_only =
      NULL; //  Only 'ZMQ_POLLIN' and 'ZMQ_POLLOUT' on 'backend_'.

    if (frontend_ != backend_) {
        poller_send_blocked = new (std::nothrow)
          zmq::socket_poller_t; //  All except 'ZMQ_POLLIN' on 'backend_'.
        poller_both_blocked = new (std::nothrow) zmq::
          socket_poller_t; //  All except 'ZMQ_POLLIN' on both 'frontend_' and 'backend_'.
        poller_frontend_only = new (std::nothrow) zmq::
          socket_poller_t; //  Only 'ZMQ_POLLIN' and 'ZMQ_POLLOUT' on 'frontend_'.
        poller_backend_only = new (std::nothrow) zmq::
          socket_poller_t; //  Only 'ZMQ_POLLIN' and 'ZMQ_POLLOUT' on 'backend_'.
        frontend_equal_to_backend = false;
    } else
        frontend_equal_to_backend = true;

    if (poller_all == NULL || poller_in == NULL || poller_control == NULL
        || poller_receive_blocked == NULL
        || ((poller_send_blocked == NULL || poller_both_blocked == NULL)
            && !frontend_equal_to_backend)) {
        PROXY_CLEANUP ();
        return close_and_return (&msg, -1);
    }

    zmq::socket_poller_t *poller_wait =
      poller_in; //  Poller for blocking wait, initially all 'ZMQ_POLLIN'.

    //  Register 'frontend_' and 'backend_' with pollers.
    rc = poller_all->add (frontend_, NULL,
                          ZMQ_POLLIN | ZMQ_POLLOUT); //  Everything.
    CHECK_RC_EXIT_ON_FAILURE ();
    rc = poller_in->add (frontend_, NULL, ZMQ_POLLIN); //  All 'ZMQ_POLLIN's.
    CHECK_RC_EXIT_ON_FAILURE ();

    if (frontend_equal_to_backend) {
        //  If frontend_==backend_ 'poller_send_blocked' and 'poller_receive_blocked' are the same,
        //  so we don't need 'poller_send_blocked'. We need only 'poller_receive_blocked'.
        //  We also don't need 'poller_both_blocked', no need to initialize it.
        rc = poller_receive_blocked->add (frontend_, NULL, ZMQ_POLLOUT);
        CHECK_RC_EXIT_ON_FAILURE ();
    } else {
        rc = poller_all->add (backend_, NULL,
                              ZMQ_POLLIN | ZMQ_POLLOUT); //  Everything.
        CHECK_RC_EXIT_ON_FAILURE ();
        rc = poller_in->add (backend_, NULL, ZMQ_POLLIN); //  All 'ZMQ_POLLIN's.
        CHECK_RC_EXIT_ON_FAILURE ();
        rc = poller_both_blocked->add (
          frontend_, NULL, ZMQ_POLLOUT); //  Waiting only for 'ZMQ_POLLOUT'.
        CHECK_RC_EXIT_ON_FAILURE ();
        rc = poller_both_blocked->add (
          backend_, NULL, ZMQ_POLLOUT); //  Waiting only for 'ZMQ_POLLOUT'.
        CHECK_RC_EXIT_ON_FAILURE ();
        rc = poller_send_blocked->add (
          backend_, NULL,
          ZMQ_POLLOUT); //  All except 'ZMQ_POLLIN' on 'backend_'.
        CHECK_RC_EXIT_ON_FAILURE ();
        rc = poller_send_blocked->add (
          frontend_, NULL,
          ZMQ_POLLIN | ZMQ_POLLOUT); //  All except 'ZMQ_POLLIN' on 'backend_'.
        CHECK_RC_EXIT_ON_FAILURE ();
        rc = poller_receive_blocked->add (
          frontend_, NULL,
          ZMQ_POLLOUT); //  All except 'ZMQ_POLLIN' on 'frontend_'.
        CHECK_RC_EXIT_ON_FAILURE ();
        rc = poller_receive_blocked->add (
          backend_, NULL,
          ZMQ_POLLIN | ZMQ_POLLOUT); //  All except 'ZMQ_POLLIN' on 'frontend_'.
        CHECK_RC_EXIT_ON_FAILURE ();
        rc =
          poller_frontend_only->add (frontend_, NULL, ZMQ_POLLIN | ZMQ_POLLOUT);
        CHECK_RC_EXIT_ON_FAILURE ();
        rc =
          poller_backend_only->add (backend_, NULL, ZMQ_POLLIN | ZMQ_POLLOUT);
        CHECK_RC_EXIT_ON_FAILURE ();
    }

    //  Register 'control_' with pollers.
    if (control_ != NULL) {
        rc = poller_all->add (control_, NULL, ZMQ_POLLIN);
        CHECK_RC_EXIT_ON_FAILURE ();
        rc = poller_in->add (control_, NULL, ZMQ_POLLIN);
        CHECK_RC_EXIT_ON_FAILURE ();
        rc = poller_control->add (
          control_, NULL,
          ZMQ_POLLIN); //  When proxy is paused we wait only for ZMQ_POLLIN on 'control_' socket.
        CHECK_RC_EXIT_ON_FAILURE ();
        rc = poller_receive_blocked->add (control_, NULL, ZMQ_POLLIN);
        CHECK_RC_EXIT_ON_FAILURE ();
        if (!frontend_equal_to_backend) {
            rc = poller_send_blocked->add (control_, NULL, ZMQ_POLLIN);
            CHECK_RC_EXIT_ON_FAILURE ();
            rc = poller_both_blocked->add (control_, NULL, ZMQ_POLLIN);
            CHECK_RC_EXIT_ON_FAILURE ();
            rc = poller_frontend_only->add (control_, NULL, ZMQ_POLLIN);
            CHECK_RC_EXIT_ON_FAILURE ();
            rc = poller_backend_only->add (control_, NULL, ZMQ_POLLIN);
            CHECK_RC_EXIT_ON_FAILURE ();
        }
    }

    bool request_processed, reply_processed;

    while (state != terminated) {
        //  Blocking wait initially only for 'ZMQ_POLLIN' - 'poller_wait' points to 'poller_in'.
        //  If one of receiving end's queue is full ('ZMQ_POLLOUT' not available),
        //  'poller_wait' is pointed to 'poller_receive_blocked', 'poller_send_blocked' or 'poller_both_blocked'.
        rc = poller_wait->wait (events, 3, -1);
        if (rc < 0 && errno == EAGAIN)
            rc = 0;
        CHECK_RC_EXIT_ON_FAILURE ();

        //  Some of events waited for by 'poller_wait' have arrived, now poll for everything without blocking.
        rc = poller_all->wait (events, 3, 0);
        if (rc < 0 && errno == EAGAIN)
            rc = 0;
        CHECK_RC_EXIT_ON_FAILURE ();

        //  Process events.
        for (int i = 0; i < rc; i++) {
            if (events[i].socket == frontend_) {
                frontend_in = (events[i].events & ZMQ_POLLIN) != 0;
                frontend_out = (events[i].events & ZMQ_POLLOUT) != 0;
            } else
              //  This 'if' needs to be after check for 'frontend_' in order never
              //  to be reached in case frontend_==backend_, so we ensure backend_in=false in that case.
              if (events[i].socket == backend_) {
                backend_in = (events[i].events & ZMQ_POLLIN) != 0;
                backend_out = (events[i].events & ZMQ_POLLOUT) != 0;
            } else if (events[i].socket == control_)
                control_in = (events[i].events & ZMQ_POLLIN) != 0;
        }


        //  Process a control command if any.
        if (control_in) {
            rc = control_->recv (&msg, 0);
            CHECK_RC_EXIT_ON_FAILURE ();
            rc = control_->getsockopt (ZMQ_RCVMORE, &more, &moresz);
            if (unlikely (rc < 0) || more) {
                PROXY_CLEANUP ();
                return close_and_return (&msg, -1);
            }

            //  Copy message to capture socket if any.
            rc = capture (capture_, &msg);
            CHECK_RC_EXIT_ON_FAILURE ();

            if (msg.size () == 5 && memcmp (msg.data (), "PAUSE", 5) == 0) {
                state = paused;
                poller_wait = poller_control;
            } else if (msg.size () == 6
                       && memcmp (msg.data (), "RESUME", 6) == 0) {
                state = active;
                poller_wait = poller_in;
            } else {
                if (msg.size () == 9
                    && memcmp (msg.data (), "TERMINATE", 9) == 0)
                    state = terminated;
                else {
                    if (msg.size () == 10
                        && memcmp (msg.data (), "STATISTICS", 10) == 0) {
                        rc = reply_stats (control_, &frontend_stats,
                                          &backend_stats);
                        CHECK_RC_EXIT_ON_FAILURE ();
                    } else {
                        //  This is an API error, we assert
                        puts ("E: invalid command sent to proxy");
                        zmq_assert (false);
                    }
                }
            }
            control_in = false;
        }

        if (state == active) {
            //  Process a request, 'ZMQ_POLLIN' on 'frontend_' and 'ZMQ_POLLOUT' on 'backend_'.
            //  In case of frontend_==backend_ there's no 'ZMQ_POLLOUT' event.
            if (frontend_in && (backend_out || frontend_equal_to_backend)) {
                rc = forward (frontend_, &frontend_stats, backend_,
                              &backend_stats, capture_, &msg);
                CHECK_RC_EXIT_ON_FAILURE ();
                request_processed = true;
                frontend_in = backend_out = false;
            } else
                request_processed = false;

            //  Process a reply, 'ZMQ_POLLIN' on 'backend_' and 'ZMQ_POLLOUT' on 'frontend_'.
            //  If 'frontend_' and 'backend_' are the same this is not needed because previous processing
            //  covers all of the cases. 'backend_in' is always false if frontend_==backend_ due to
            //  design in 'for' event processing loop.
            if (backend_in && frontend_out) {
                rc = forward (backend_, &backend_stats, frontend_,
                              &frontend_stats, capture_, &msg);
                CHECK_RC_EXIT_ON_FAILURE ();
                reply_processed = true;
                backend_in = frontend_out = false;
            } else
                reply_processed = false;

            if (request_processed || reply_processed) {
                //  If request/reply is processed that means we had at least one 'ZMQ_POLLOUT' event.
                //  Enable corresponding 'ZMQ_POLLIN' for blocking wait if any was disabled.
                if (poller_wait != poller_in) {
                    if (request_processed) { //  'frontend_' -> 'backend_'
                        if (poller_wait == poller_both_blocked)
                            poller_wait = poller_send_blocked;
                        else if (poller_wait == poller_receive_blocked
                                 || poller_wait == poller_frontend_only)
                            poller_wait = poller_in;
                    }
                    if (reply_processed) { //  'backend_' -> 'frontend_'
                        if (poller_wait == poller_both_blocked)
                            poller_wait = poller_receive_blocked;
                        else if (poller_wait == poller_send_blocked
                                 || poller_wait == poller_backend_only)
                            poller_wait = poller_in;
                    }
                }
            } else {
                //  No requests have been processed, there were no 'ZMQ_POLLIN' with corresponding 'ZMQ_POLLOUT' events.
                //  That means that out queue(s) is/are full or one out queue is full and second one has no messages to process.
                //  Disable receiving 'ZMQ_POLLIN' for sockets for which there's no 'ZMQ_POLLOUT',
                //  or wait only on both 'backend_''s or 'frontend_''s 'ZMQ_POLLIN' and 'ZMQ_POLLOUT'.
                if (frontend_in) {
                    if (frontend_out)
                        // If frontend_in and frontend_out are true, obviously backend_in and backend_out are both false.
                        // In that case we need to wait for both 'ZMQ_POLLIN' and 'ZMQ_POLLOUT' only on 'backend_'.
                        // We'll never get here in case of frontend_==backend_ because then frontend_out will always be false.
                        poller_wait = poller_backend_only;
                    else {
                        if (poller_wait == poller_send_blocked)
                            poller_wait = poller_both_blocked;
                        else if (poller_wait == poller_in)
                            poller_wait = poller_receive_blocked;
                    }
                }
                if (backend_in) {
                    //  Will never be reached if frontend_==backend_, 'backend_in' will
                    //  always be false due to design in 'for' event processing loop.
                    if (backend_out)
                        // If backend_in and backend_out are true, obviously frontend_in and frontend_out are both false.
                        // In that case we need to wait for both 'ZMQ_POLLIN' and 'ZMQ_POLLOUT' only on 'frontend_'.
                        poller_wait = poller_frontend_only;
                    else {
                        if (poller_wait == poller_receive_blocked)
                            poller_wait = poller_both_blocked;
                        else if (poller_wait == poller_in)
                            poller_wait = poller_send_blocked;
                    }
                }
            }
        }
    }
    PROXY_CLEANUP ();
    return close_and_return (&msg, 0);
}

#else //  ZMQ_HAVE_POLLER

int zmq::proxy (class socket_base_t *frontend_,
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
    zmq_pollitem_t items[] = {{frontend_, 0, ZMQ_POLLIN, 0},
                              {backend_, 0, ZMQ_POLLIN, 0},
                              {control_, 0, ZMQ_POLLIN, 0}};
    int qt_poll_items = (control_ ? 3 : 2);
    zmq_pollitem_t itemsout[] = {{frontend_, 0, ZMQ_POLLOUT, 0},
                                 {backend_, 0, ZMQ_POLLOUT, 0}};

    zmq_socket_stats_t frontend_stats;
    memset (&frontend_stats, 0, sizeof (frontend_stats));
    zmq_socket_stats_t backend_stats;
    memset (&backend_stats, 0, sizeof (backend_stats));

    //  Proxy can be in these three states
    enum
    {
        active,
        paused,
        terminated
    } state = active;

    while (state != terminated) {
        //  Wait while there are either requests or replies to process.
        rc = zmq_poll (&items[0], qt_poll_items, -1);
        if (unlikely (rc < 0))
            return close_and_return (&msg, -1);

        //  Get the pollout separately because when combining this with pollin it maxes the CPU
        //  because pollout shall most of the time return directly.
        //  POLLOUT is only checked when frontend and backend sockets are not the same.
        if (frontend_ != backend_) {
            rc = zmq_poll (&itemsout[0], 2, 0);
            if (unlikely (rc < 0)) {
                return close_and_return (&msg, -1);
            }
        }

        //  Process a control command if any
        if (control_ && items[2].revents & ZMQ_POLLIN) {
            rc = control_->recv (&msg, 0);
            if (unlikely (rc < 0))
                return close_and_return (&msg, -1);

            moresz = sizeof more;
            rc = control_->getsockopt (ZMQ_RCVMORE, &more, &moresz);
            if (unlikely (rc < 0) || more)
                return close_and_return (&msg, -1);

            //  Copy message to capture socket if any
            rc = capture (capture_, &msg);
            if (unlikely (rc < 0))
                return close_and_return (&msg, -1);

            if (msg.size () == 5 && memcmp (msg.data (), "PAUSE", 5) == 0)
                state = paused;
            else if (msg.size () == 6 && memcmp (msg.data (), "RESUME", 6) == 0)
                state = active;
            else if (msg.size () == 9
                     && memcmp (msg.data (), "TERMINATE", 9) == 0)
                state = terminated;
            else {
                if (msg.size () == 10
                    && memcmp (msg.data (), "STATISTICS", 10) == 0) {
                    rc =
                      reply_stats (control_, &frontend_stats, &backend_stats);
                    if (unlikely (rc < 0))
                        return close_and_return (&msg, -1);
                } else {
                    //  This is an API error, we assert
                    puts ("E: invalid command sent to proxy");
                    zmq_assert (false);
                }
            }
        }
        //  Process a request
        if (state == active && items[0].revents & ZMQ_POLLIN
            && (frontend_ == backend_ || itemsout[1].revents & ZMQ_POLLOUT)) {
            rc = forward (frontend_, &frontend_stats, backend_, &backend_stats,
                          capture_, &msg);
            if (unlikely (rc < 0))
                return close_and_return (&msg, -1);
        }
        //  Process a reply
        if (state == active && frontend_ != backend_
            && items[1].revents & ZMQ_POLLIN
            && itemsout[0].revents & ZMQ_POLLOUT) {
            rc = forward (backend_, &backend_stats, frontend_, &frontend_stats,
                          capture_, &msg);
            if (unlikely (rc < 0))
                return close_and_return (&msg, -1);
        }
    }

    return close_and_return (&msg, 0);
}

#endif //  ZMQ_HAVE_POLLER
