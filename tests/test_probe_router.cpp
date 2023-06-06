/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

SETUP_TEARDOWN_TESTCONTEXT

void test_probe_router_router ()
{
    //  Create server and bind to endpoint
    void *server = test_context_socket (ZMQ_ROUTER);

    char my_endpoint[MAX_SOCKET_STRING];
    bind_loopback_ipv4 (server, my_endpoint, sizeof (my_endpoint));

    //  Create client and connect to server, doing a probe
    void *client = test_context_socket (ZMQ_ROUTER);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (client, ZMQ_ROUTING_ID, "X", 1));
    int probe = 1;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (client, ZMQ_PROBE_ROUTER, &probe, sizeof (probe)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (client, my_endpoint));

    //  We expect a routing id=X + empty message from client
    recv_string_expect_success (server, "X", 0);
    unsigned char buffer[255];
    TEST_ASSERT_EQUAL_INT (
      0, TEST_ASSERT_SUCCESS_ERRNO (zmq_recv (server, buffer, 255, 0)));

    //  Send a message to client now
    send_string_expect_success (server, "X", ZMQ_SNDMORE);
    send_string_expect_success (server, "Hello", 0);

    // receive the routing ID, which is auto-generated in this case, since the
    // peer did not set one explicitly
    TEST_ASSERT_EQUAL_INT (
      5, TEST_ASSERT_SUCCESS_ERRNO (zmq_recv (client, buffer, 255, 0)));

    recv_string_expect_success (client, "Hello", 0);

    test_context_socket_close (server);
    test_context_socket_close (client);
}

void test_probe_router_dealer ()
{
    //  Create server and bind to endpoint
    void *server = test_context_socket (ZMQ_ROUTER);

    char my_endpoint[MAX_SOCKET_STRING];
    bind_loopback_ipv4 (server, my_endpoint, sizeof (my_endpoint));

    //  Create client and connect to server, doing a probe
    void *client = test_context_socket (ZMQ_DEALER);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (client, ZMQ_ROUTING_ID, "X", 1));
    int probe = 1;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (client, ZMQ_PROBE_ROUTER, &probe, sizeof (probe)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (client, my_endpoint));

    //  We expect a routing id=X + empty message from client
    recv_string_expect_success (server, "X", 0);
    unsigned char buffer[255];
    TEST_ASSERT_SUCCESS_ERRNO (zmq_recv (server, buffer, 255, 0));

    //  Send a message to client now
    send_string_expect_success (server, "X", ZMQ_SNDMORE);
    send_string_expect_success (server, "Hello", 0);

    recv_string_expect_success (client, "Hello", 0);

    test_context_socket_close (server);
    test_context_socket_close (client);
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();

    RUN_TEST (test_probe_router_router);
    RUN_TEST (test_probe_router_dealer);

    return UNITY_END ();
}
