/*
    Copyright (c) 2007-2017 Contributors as noted in the AUTHORS file

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

#ifndef __TESTUTIL_MONITORING_HPP_INCLUDED__
#define __TESTUTIL_MONITORING_HPP_INCLUDED__

#include "testutil.hpp"

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

//  General, i.e. non-security specific, monitor utilities

//  Read one event off the monitor socket; return value and address
//  by reference, if not null, and event number by value. Returns -1
//  in case of error.

static int get_monitor_event_internal (void *monitor_,
                                       int *value_,
                                       char **address_,
                                       int recv_flag_)
{
    //  First frame in message contains event number and value
    zmq_msg_t msg;
    zmq_msg_init (&msg);
    if (zmq_msg_recv (&msg, monitor_, recv_flag_) == -1) {
        assert (errno == EAGAIN);
        return -1; //  timed out or no message available
    }
    assert (zmq_msg_more (&msg));

    uint8_t *data = (uint8_t *) zmq_msg_data (&msg);
    uint16_t event = *(uint16_t *) (data);
    if (value_)
        memcpy (value_, data + 2, sizeof (uint32_t));

    //  Second frame in message contains event address
    zmq_msg_init (&msg);
    int res = zmq_msg_recv (&msg, monitor_, recv_flag_) == -1;
    assert (res != -1);
    assert (!zmq_msg_more (&msg));

    if (address_) {
        uint8_t *data = (uint8_t *) zmq_msg_data (&msg);
        size_t size = zmq_msg_size (&msg);
        *address_ = (char *) malloc (size + 1);
        memcpy (*address_, data, size);
        *address_[size] = 0;
    }
    return event;
}

int get_monitor_event_with_timeout (void *monitor_,
                                    int *value_,
                                    char **address_,
                                    int timeout_)
{
    int res;
    if (timeout_ == -1) {
        // process infinite timeout in small steps to allow the user
        // to see some information on the console

        int timeout_step = 250;
        int wait_time = 0;
        zmq_setsockopt (monitor_, ZMQ_RCVTIMEO, &timeout_step,
                        sizeof (timeout_step));
        while (
          (res = get_monitor_event_internal (monitor_, value_, address_, 0))
          == -1) {
            wait_time += timeout_step;
            fprintf (stderr, "Still waiting for monitor event after %i ms\n",
                     wait_time);
        }
    } else {
        zmq_setsockopt (monitor_, ZMQ_RCVTIMEO, &timeout_, sizeof (timeout_));
        res = get_monitor_event_internal (monitor_, value_, address_, 0);
    }
    int timeout_infinite = -1;
    zmq_setsockopt (monitor_, ZMQ_RCVTIMEO, &timeout_infinite,
                    sizeof (timeout_infinite));
    return res;
}

int get_monitor_event (void *monitor_, int *value_, char **address_)
{
    return get_monitor_event_with_timeout (monitor_, value_, address_, -1);
}

void expect_monitor_event (void *monitor_, int expected_event_)
{
    int event = get_monitor_event (monitor_, NULL, NULL);
    if (event != expected_event_) {
        fprintf (stderr, "Expected monitor event %x but received %x\n",
                 expected_event_, event);
        assert (event == expected_event_);
    }
}

void print_unexpected_event (int event_,
                             int err_,
                             int expected_event_,
                             int expected_err_)
{
    fprintf (stderr,
             "Unexpected event: 0x%x, value = %i/0x%x (expected: 0x%x, value "
             "= %i/0x%x)\n",
             event_, err_, err_, expected_event_, expected_err_, expected_err_);
}

//  expects that one or more occurrences of the expected event are received
//  via the specified socket monitor
//  returns the number of occurrences of the expected event
//  interrupts, if a ZMQ_EVENT_HANDSHAKE_FAILED_NO_DETAIL with EPIPE, ECONNRESET
//  or ECONNABORTED occurs; in this case, 0 is returned
//  this should be investigated further, see
//  https://github.com/zeromq/libzmq/issues/2644
int expect_monitor_event_multiple (void *server_mon_,
                                   int expected_event_,
                                   int expected_err_ = -1,
                                   bool optional_ = false)
{
    int count_of_expected_events = 0;
    int client_closed_connection = 0;
    int timeout = 250;
    int wait_time = 0;

    int event;
    int err;
    while ((event =
              get_monitor_event_with_timeout (server_mon_, &err, NULL, timeout))
             != -1
           || !count_of_expected_events) {
        if (event == -1) {
            if (optional_)
                break;
            wait_time += timeout;
            fprintf (stderr,
                     "Still waiting for first event after %ims (expected event "
                     "%x (value %i/0x%x))\n",
                     wait_time, expected_event_, expected_err_, expected_err_);
            continue;
        }
        // ignore errors with EPIPE/ECONNRESET/ECONNABORTED, which can happen
        // ECONNRESET can happen on very slow machines, when the engine writes
        // to the peer and then tries to read the socket before the peer reads
        // ECONNABORTED happens when a client aborts a connection via RST/timeout
        if (event == ZMQ_EVENT_HANDSHAKE_FAILED_NO_DETAIL
            && ((err == EPIPE && expected_err_ != EPIPE) || err == ECONNRESET
                || err == ECONNABORTED)) {
            fprintf (stderr,
                     "Ignored event (skipping any further events): %x (err = "
                     "%i == %s)\n",
                     event, err, zmq_strerror (err));
            client_closed_connection = 1;
            break;
        }
        if (event != expected_event_
            || (-1 != expected_err_ && err != expected_err_)) {
            print_unexpected_event (event, err, expected_event_, expected_err_);
            assert (false);
        }
        ++count_of_expected_events;
    }
    assert (optional_ || count_of_expected_events > 0
            || client_closed_connection);

    return count_of_expected_events;
}

#ifdef ZMQ_BUILD_DRAFT_API
static int64_t get_monitor_event_internal_v2 (void *monitor_,
                                              uint64_t *value_,
                                              char **local_address_,
                                              char **remote_address_,
                                              int recv_flag_)
{
    //  First frame in message contains event number
    zmq_msg_t msg;
    zmq_msg_init (&msg);
    if (zmq_msg_recv (&msg, monitor_, recv_flag_) == -1) {
        assert (errno == EAGAIN);
        return -1; //  timed out or no message available
    }
    assert (zmq_msg_more (&msg));
    assert (sizeof (uint64_t) == zmq_msg_size (&msg));

    uint64_t event;
    memcpy (&event, zmq_msg_data (&msg), sizeof event);

    //  Second frame in message contains event value
    zmq_msg_init (&msg);
    if (zmq_msg_recv (&msg, monitor_, recv_flag_) == -1) {
        assert (errno == EAGAIN);
        return -1; //  timed out or no message available
    }
    assert (zmq_msg_more (&msg));
    assert (sizeof (uint64_t) == zmq_msg_size (&msg));

    if (value_)
        memcpy (value_, zmq_msg_data (&msg), sizeof *value_);

    //  Third frame in message contains local address
    zmq_msg_init (&msg);
    int res = zmq_msg_recv (&msg, monitor_, recv_flag_) == -1;
    assert (res != -1);
    assert (zmq_msg_more (&msg));

    if (local_address_) {
        uint8_t *data = (uint8_t *) zmq_msg_data (&msg);
        size_t size = zmq_msg_size (&msg);
        *local_address_ = (char *) malloc (size + 1);
        memcpy (*local_address_, data, size);
        *local_address_[size] = 0;
    }

    //  Fourth and last frame in message contains remote address
    zmq_msg_init (&msg);
    res = zmq_msg_recv (&msg, monitor_, recv_flag_) == -1;
    assert (res != -1);
    assert (!zmq_msg_more (&msg));

    if (remote_address_) {
        uint8_t *data = (uint8_t *) zmq_msg_data (&msg);
        size_t size = zmq_msg_size (&msg);
        *remote_address_ = (char *) malloc (size + 1);
        memcpy (*remote_address_, data, size);
        *remote_address_[size] = 0;
    }
    return event;
}

int64_t get_monitor_event_with_timeout_v2 (void *monitor_,
                                           uint64_t *value_,
                                           char **local_address_,
                                           char **remote_address_,
                                           int timeout_)
{
    int res;
    if (timeout_ == -1) {
        // process infinite timeout in small steps to allow the user
        // to see some information on the console

        int timeout_step = 250;
        int wait_time = 0;
        zmq_setsockopt (monitor_, ZMQ_RCVTIMEO, &timeout_step,
                        sizeof (timeout_step));
        while ((res = get_monitor_event_internal_v2 (
                  monitor_, value_, local_address_, remote_address_, 0))
               == -1) {
            wait_time += timeout_step;
            fprintf (stderr, "Still waiting for monitor event after %i ms\n",
                     wait_time);
        }
    } else {
        zmq_setsockopt (monitor_, ZMQ_RCVTIMEO, &timeout_, sizeof (timeout_));
        res = get_monitor_event_internal_v2 (monitor_, value_, local_address_,
                                             remote_address_, 0);
    }
    int timeout_infinite = -1;
    zmq_setsockopt (monitor_, ZMQ_RCVTIMEO, &timeout_infinite,
                    sizeof (timeout_infinite));
    return res;
}

int64_t get_monitor_event_v2 (void *monitor_,
                              uint64_t *value_,
                              char **local_address_,
                              char **remote_address_)
{
    return get_monitor_event_with_timeout_v2 (monitor_, value_, local_address_,
                                              remote_address_, -1);
}

void expect_monitor_event_v2 (void *monitor_, int64_t expected_event_)
{
    int64_t event = get_monitor_event_v2 (monitor_, NULL, NULL, NULL);
    if (event != expected_event_) {
        fprintf (stderr,
                 "Expected monitor event %" PRIx64 " but received %" PRIx64
                 "\n",
                 expected_event_, event);
        assert (event == expected_event_);
    }
}
#endif

#endif
