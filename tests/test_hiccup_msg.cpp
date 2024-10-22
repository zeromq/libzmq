/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

SETUP_TEARDOWN_TESTCONTEXT

void test ()
{
    char address[MAX_SOCKET_STRING];
    size_t addr_length = sizeof (address);

    //  Create a server
    void *server = test_context_socket (ZMQ_SERVER);

    //  bind server
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (server, "tcp://127.0.0.1:*"));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (server, ZMQ_LAST_ENDPOINT, address, &addr_length));

    //  Create a client
    void *client = test_context_socket (ZMQ_CLIENT);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (client, ZMQ_HELLO_MSG, "HELLO", 5));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (client, ZMQ_HICCUP_MSG, "HICCUP", 6));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (client, address));

    // Receive the hello message from client
    recv_string_expect_success (server, "HELLO", 0);

    // Kill the server
    test_context_socket_close (server);

    // Receive the hiccup message
    recv_string_expect_success (client, "HICCUP", 0);

    //  Clean up.
    test_context_socket_close (client);
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test);
    return UNITY_END ();
}
