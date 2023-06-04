/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

SETUP_TEARDOWN_TESTCONTEXT

void test (const char *address)
{
    //  Create a router
    void *router = test_context_socket (ZMQ_ROUTER);
    char my_endpoint[MAX_SOCKET_STRING];

    //  set router socket options
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (router, ZMQ_HELLO_MSG, "H", 1));

    //  bind router
    test_bind (router, address, my_endpoint, MAX_SOCKET_STRING);

    //  Create a dealer
    void *dealer = test_context_socket (ZMQ_DEALER);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (dealer, my_endpoint));

    // Receive the hello message
    recv_string_expect_success (dealer, "H", 0);

    //  Clean up.
    test_context_socket_close (dealer);
    test_context_socket_close (router);
}

void test_tcp ()
{
    test ("tcp://127.0.0.1:*");
}

void test_inproc ()
{
    test ("inproc://hello-msg");
}

void test_inproc_late_bind ()
{
    char address[] = "inproc://late-hello-msg";

    //  Create a server
    void *server = test_context_socket (ZMQ_SERVER);

    //  set server socket options
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (server, ZMQ_HELLO_MSG, "W", 1));

    //  Create a dealer
    void *client = test_context_socket (ZMQ_CLIENT);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (client, ZMQ_HELLO_MSG, "H", 1));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (client, address));

    //  bind server after the dealer
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (server, address));

    // Receive the welcome message from server
    recv_string_expect_success (client, "W", 0);

    // Receive the hello message from client
    recv_string_expect_success (server, "H", 0);

    //  Clean up.
    test_context_socket_close (client);
    test_context_socket_close (server);
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_tcp);
    RUN_TEST (test_inproc);
    RUN_TEST (test_inproc_late_bind);
    return UNITY_END ();
}
