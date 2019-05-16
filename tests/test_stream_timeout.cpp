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

#include "testutil.hpp"
#include "testutil_unity.hpp"

#include <stdlib.h>
#include <string.h>

SETUP_TEARDOWN_TESTCONTEXT

//  Read one event off the monitor socket; return value and address
//  by reference, if not null, and event number by value. Returns -1
//  in case of error.

static int get_monitor_event (void *monitor_, int *value_, char **address_)
{
    //  First frame in message contains event number and value
    zmq_msg_t msg;
    zmq_msg_init (&msg);
    if (zmq_msg_recv (&msg, monitor_, 0) == -1)
        return -1; //  Interruped, presumably
    TEST_ASSERT_TRUE (zmq_msg_more (&msg));

    uint8_t *data = (uint8_t *) zmq_msg_data (&msg);
    uint16_t event = *(uint16_t *) (data);
    if (value_)
        *value_ = *(uint32_t *) (data + 2);

    //  Second frame in message contains event address
    zmq_msg_init (&msg);
    if (zmq_msg_recv (&msg, monitor_, 0) == -1)
        return -1; //  Interruped, presumably
    TEST_ASSERT_TRUE (!zmq_msg_more (&msg));

    if (address_) {
        uint8_t *data = (uint8_t *) zmq_msg_data (&msg);
        size_t size = zmq_msg_size (&msg);
        *address_ = (char *) malloc (size + 1);
        memcpy (*address_, data, size);
        *address_[size] = 0;
    }
    return event;
}

static void test_stream_handshake_timeout_accept ()
{
    char my_endpoint[MAX_SOCKET_STRING];

    //  We use this socket in raw mode, to make a connection and send nothing
    void *stream = test_context_socket (ZMQ_STREAM);

    int zero = 0;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (stream, ZMQ_LINGER, &zero, sizeof (zero)));

    //  We'll be using this socket to test TCP stream handshake timeout
    void *dealer = test_context_socket (ZMQ_DEALER);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (dealer, ZMQ_LINGER, &zero, sizeof (zero)));
    int val, tenth = 100;
    size_t vsize = sizeof (val);

    // check for the expected default handshake timeout value - 30 sec
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (dealer, ZMQ_HANDSHAKE_IVL, &val, &vsize));
    TEST_ASSERT_EQUAL (sizeof (val), vsize);
    TEST_ASSERT_EQUAL_INT (30000, val);
    // make handshake timeout faster - 1/10 sec
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (dealer, ZMQ_HANDSHAKE_IVL, &tenth, sizeof (tenth)));
    vsize = sizeof (val);
    // make sure zmq_setsockopt changed the value
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (dealer, ZMQ_HANDSHAKE_IVL, &val, &vsize));
    TEST_ASSERT_EQUAL (sizeof (val), vsize);
    TEST_ASSERT_EQUAL_INT (tenth, val);

    //  Create and connect a socket for collecting monitor events on dealer
    void *dealer_mon = test_context_socket (ZMQ_PAIR);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_socket_monitor (
      dealer, "inproc://monitor-dealer",
      ZMQ_EVENT_CONNECTED | ZMQ_EVENT_DISCONNECTED | ZMQ_EVENT_ACCEPTED));

    //  Connect to the inproc endpoint so we'll get events
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_connect (dealer_mon, "inproc://monitor-dealer"));

    // bind dealer socket to accept connection from non-sending stream socket
    bind_loopback_ipv4 (dealer, my_endpoint, sizeof my_endpoint);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (stream, my_endpoint));

    // we should get ZMQ_EVENT_ACCEPTED and then ZMQ_EVENT_DISCONNECTED
    int event = get_monitor_event (dealer_mon, NULL, NULL);
    TEST_ASSERT_EQUAL_INT (ZMQ_EVENT_ACCEPTED, event);
    event = get_monitor_event (dealer_mon, NULL, NULL);
    TEST_ASSERT_EQUAL_INT (ZMQ_EVENT_DISCONNECTED, event);

    test_context_socket_close (dealer);
    test_context_socket_close (dealer_mon);
    test_context_socket_close (stream);
}

static void test_stream_handshake_timeout_connect ()
{
    char my_endpoint[MAX_SOCKET_STRING];

    //  We use this socket in raw mode, to accept a connection and send nothing
    void *stream = test_context_socket (ZMQ_STREAM);

    int zero = 0;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (stream, ZMQ_LINGER, &zero, sizeof (zero)));

    bind_loopback_ipv4 (stream, my_endpoint, sizeof my_endpoint);

    //  We'll be using this socket to test TCP stream handshake timeout
    void *dealer = test_context_socket (ZMQ_DEALER);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (dealer, ZMQ_LINGER, &zero, sizeof (zero)));
    int val, tenth = 100;
    size_t vsize = sizeof (val);

    // check for the expected default handshake timeout value - 30 sec
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (dealer, ZMQ_HANDSHAKE_IVL, &val, &vsize));
    TEST_ASSERT_EQUAL (sizeof (val), vsize);
    TEST_ASSERT_EQUAL_INT (30000, val);
    // make handshake timeout faster - 1/10 sec
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (dealer, ZMQ_HANDSHAKE_IVL, &tenth, sizeof (tenth)));
    vsize = sizeof (val);
    // make sure zmq_setsockopt changed the value
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (dealer, ZMQ_HANDSHAKE_IVL, &val, &vsize));
    TEST_ASSERT_EQUAL (sizeof (val), vsize);
    TEST_ASSERT_EQUAL_INT (tenth, val);

    //  Create and connect a socket for collecting monitor events on dealer
    void *dealer_mon = test_context_socket (ZMQ_PAIR);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_socket_monitor (
      dealer, "inproc://monitor-dealer",
      ZMQ_EVENT_CONNECTED | ZMQ_EVENT_DISCONNECTED | ZMQ_EVENT_ACCEPTED));

    //  Connect to the inproc endpoint so we'll get events
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_connect (dealer_mon, "inproc://monitor-dealer"));

    // connect dealer socket to non-sending stream socket
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (dealer, my_endpoint));

    // we should get ZMQ_EVENT_CONNECTED and then ZMQ_EVENT_DISCONNECTED
    int event = get_monitor_event (dealer_mon, NULL, NULL);
    TEST_ASSERT_EQUAL_INT (ZMQ_EVENT_CONNECTED, event);
    event = get_monitor_event (dealer_mon, NULL, NULL);
    TEST_ASSERT_EQUAL_INT (ZMQ_EVENT_DISCONNECTED, event);

    test_context_socket_close (dealer);
    test_context_socket_close (dealer_mon);
    test_context_socket_close (stream);
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_stream_handshake_timeout_accept);
    RUN_TEST (test_stream_handshake_timeout_connect);
    return UNITY_END ();
}
