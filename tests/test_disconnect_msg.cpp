/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

SETUP_TEARDOWN_TESTCONTEXT

void test (const char *address)
{
    //  Create a server
    void *server = test_context_socket (ZMQ_SERVER);

    //  set server socket options
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (server, ZMQ_DISCONNECT_MSG, "D", 1));

    //  bind server
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (server, address));

    //  Create a client
    void *client = test_context_socket (ZMQ_CLIENT);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (client, ZMQ_HELLO_MSG, "H", 1));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (client, address));

    // Receive the hello message from client
    recv_string_expect_success (server, "H", 0);

    // Kill the client
    test_context_socket_close (client);

    // Receive the disconnect message
    recv_string_expect_success (server, "D", 0);

    //  Clean up.
    test_context_socket_close (server);
}

void test_tcp ()
{
    test ("tcp://127.0.0.1:5569");
}

void test_inproc ()
{
    test ("inproc://disconnect-msg");
}


void test_inproc_disconnect ()
{
    const char *address = "inproc://disconnect-msg";

    //  Create a server
    void *server = test_context_socket (ZMQ_SERVER);

    //  set server socket options
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (server, ZMQ_DISCONNECT_MSG, "D", 1));

    //  bind server
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (server, address));

    //  Create a client
    void *client = test_context_socket (ZMQ_CLIENT);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (client, ZMQ_HELLO_MSG, "H", 1));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (client, address));

    // Receive the hello message from client
    recv_string_expect_success (server, "H", 0);

    // disconnect the client
    TEST_ASSERT_SUCCESS_ERRNO (zmq_disconnect (client, address));

    // Receive the disconnect message
    recv_string_expect_success (server, "D", 0);

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
    RUN_TEST (test_inproc_disconnect);
    return UNITY_END ();
}
