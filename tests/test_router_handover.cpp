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

void test_with_handover ()
{
    char my_endpoint[MAX_SOCKET_STRING];
    void *router = test_context_socket (ZMQ_ROUTER);
    bind_loopback_ipv4 (router, my_endpoint, sizeof my_endpoint);

    // Enable the handover flag
    int handover = 1;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (router, ZMQ_ROUTER_HANDOVER,
                                               &handover, sizeof (handover)));

    //  Create dealer called "X" and connect it to our router
    void *dealer_one = test_context_socket (ZMQ_DEALER);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (dealer_one, ZMQ_ROUTING_ID, "X", 1));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (dealer_one, my_endpoint));

    //  Get message from dealer to know when connection is ready
    char buffer[255];
    send_string_expect_success (dealer_one, "Hello", 0);

    recv_string_expect_success (router, "X", 0);
    recv_string_expect_success (router, "Hello", 0);

    // Now create a second dealer that uses the same routing id
    void *dealer_two = test_context_socket (ZMQ_DEALER);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (dealer_two, ZMQ_ROUTING_ID, "X", 1));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (dealer_two, my_endpoint));

    //  Get message from dealer to know when connection is ready
    send_string_expect_success (dealer_two, "Hello", 0);

    recv_string_expect_success (router, "X", 0);
    recv_string_expect_success (router, "Hello", 0);

    //  Send a message to 'X' routing id. This should be delivered
    //  to the second dealer, instead of the first because of the handover.
    send_string_expect_success (router, "X", ZMQ_SNDMORE);
    send_string_expect_success (router, "Hello", 0);

    //  Ensure that the first dealer doesn't receive the message
    //  but the second one does
    const int timeout = SETTLE_TIME;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (dealer_one, ZMQ_RCVTIMEO, &timeout, sizeof timeout));
    TEST_ASSERT_FAILURE_ERRNO (EAGAIN, zmq_recv (dealer_one, buffer, 255, 0));

    recv_string_expect_success (dealer_two, "Hello", 0);

    test_context_socket_close (router);
    test_context_socket_close (dealer_one);
    test_context_socket_close (dealer_two);
}

void test_without_handover ()
{
    size_t len = MAX_SOCKET_STRING;
    char my_endpoint[MAX_SOCKET_STRING];
    void *router = test_context_socket (ZMQ_ROUTER);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (router, "tcp://127.0.0.1:*"));

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (router, ZMQ_LAST_ENDPOINT, my_endpoint, &len));

    //  Create dealer called "X" and connect it to our router
    void *dealer_one = test_context_socket (ZMQ_DEALER);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (dealer_one, ZMQ_ROUTING_ID, "X", 1));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (dealer_one, my_endpoint));

    //  Get message from dealer to know when connection is ready
    char buffer[255];
    send_string_expect_success (dealer_one, "Hello", 0);

    recv_string_expect_success (router, "X", 0);
    recv_string_expect_success (router, "Hello", 0);

    // Now create a second dealer that uses the same routing id
    void *dealer_two = test_context_socket (ZMQ_DEALER);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (dealer_two, ZMQ_ROUTING_ID, "X", 1));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (dealer_two, my_endpoint));

    //  Send message from second dealer
    send_string_expect_success (dealer_two, "Hello", 0);

    //  This should be ignored by the router
    const int timeout = SETTLE_TIME;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (router, ZMQ_RCVTIMEO, &timeout, sizeof timeout));
    TEST_ASSERT_FAILURE_ERRNO (EAGAIN, zmq_recv (router, buffer, 255, 0));

    //  Send a message to 'X' routing id. This should be delivered
    //  to the second dealer, instead of the first because of the handover.
    send_string_expect_success (router, "X", ZMQ_SNDMORE);
    send_string_expect_success (router, "Hello", 0);

    //  Ensure that the second dealer doesn't receive the message
    //  but the first one does
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (dealer_two, ZMQ_RCVTIMEO, &timeout, sizeof timeout));
    TEST_ASSERT_FAILURE_ERRNO (EAGAIN, zmq_recv (dealer_two, buffer, 255, 0));

    recv_string_expect_success (dealer_one, "Hello", 0);

    test_context_socket_close (router);
    test_context_socket_close (dealer_one);
    test_context_socket_close (dealer_two);
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_with_handover);
    RUN_TEST (test_without_handover);
    return UNITY_END ();
}
