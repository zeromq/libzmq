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

SETUP_TEARDOWN_TESTCONTEXT

// DEBUG shouldn't be defined in sources as it will cause a redefined symbol
// error when it is defined in the build configuration. It appears that the
// intent here is to semi-permanently disable DEBUG tracing statements, so the
// implementation is changed to accomodate that intent.
//#define DEBUG 0
#define TRACE_ENABLED 0

void test_router_mandatory_hwm ()
{
    if (TRACE_ENABLED)
        fprintf (stderr, "Staring router mandatory HWM test ...\n");
    char my_endpoint[MAX_SOCKET_STRING];
    void *router = test_context_socket (ZMQ_ROUTER);

    // Configure router socket to mandatory routing and set HWM and linger
    int mandatory = 1;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (router, ZMQ_ROUTER_MANDATORY,
                                               &mandatory, sizeof (mandatory)));
    int sndhwm = 1;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (router, ZMQ_SNDHWM, &sndhwm, sizeof (sndhwm)));
    int linger = 1;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (router, ZMQ_LINGER, &linger, sizeof (linger)));

    bind_loopback_ipv4 (router, my_endpoint, sizeof my_endpoint);

    //  Create dealer called "X" and connect it to our router, configure HWM
    void *dealer = test_context_socket (ZMQ_DEALER);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (dealer, ZMQ_ROUTING_ID, "X", 1));
    int rcvhwm = 1;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (dealer, ZMQ_RCVHWM, &rcvhwm, sizeof (rcvhwm)));

    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (dealer, my_endpoint));

    //  Get message from dealer to know when connection is ready
    send_string_expect_success (dealer, "Hello", 0);
    recv_string_expect_success (router, "X", 0);

    int i;
    const int buf_size = 65536;
    const uint8_t buf[buf_size] = {0};
    // Send first batch of messages
    for (i = 0; i < 100000; ++i) {
        if (TRACE_ENABLED)
            fprintf (stderr, "Sending message %d ...\n", i);
        const int rc = zmq_send (router, "X", 1, ZMQ_DONTWAIT | ZMQ_SNDMORE);
        if (rc == -1 && zmq_errno () == EAGAIN)
            break;
        TEST_ASSERT_EQUAL_INT (1, rc);
        send_array_expect_success (router, buf, ZMQ_DONTWAIT);
    }
    // This should fail after one message but kernel buffering could
    // skew results
    TEST_ASSERT_LESS_THAN_INT (10, i);
    msleep (1000);
    // Send second batch of messages
    for (; i < 100000; ++i) {
        if (TRACE_ENABLED)
            fprintf (stderr, "Sending message %d (part 2) ...\n", i);
        const int rc = zmq_send (router, "X", 1, ZMQ_DONTWAIT | ZMQ_SNDMORE);
        if (rc == -1 && zmq_errno () == EAGAIN)
            break;
        TEST_ASSERT_EQUAL_INT (1, rc);
        send_array_expect_success (router, buf, ZMQ_DONTWAIT);
    }
    // This should fail after two messages but kernel buffering could
    // skew results
    TEST_ASSERT_LESS_THAN_INT (20, i);

    if (TRACE_ENABLED)
        fprintf (stderr, "Done sending messages.\n");

    test_context_socket_close (router);
    test_context_socket_close (dealer);
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_router_mandatory_hwm);
    return UNITY_END ();
}
