/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

SETUP_TEARDOWN_TESTCONTEXT

void test_invalid_rep ()
{
    //  Create REQ/ROUTER wiring.
    void *router_socket = test_context_socket (ZMQ_ROUTER);
    void *req_socket = test_context_socket (ZMQ_REQ);

    int linger = 0;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (router_socket, ZMQ_LINGER, &linger, sizeof (int)));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (req_socket, ZMQ_LINGER, &linger, sizeof (int)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (router_socket, "inproc://hi"));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (req_socket, "inproc://hi"));

    //  Initial request.
    send_string_expect_success (req_socket, "r", 0);

    //  Receive the request.
    char addr[32];
    int addr_size;
    char bottom[1];
    char body[1];
    TEST_ASSERT_SUCCESS_ERRNO (
      addr_size = zmq_recv (router_socket, addr, sizeof (addr), 0));
    TEST_ASSERT_EQUAL_INT (0, TEST_ASSERT_SUCCESS_ERRNO (zmq_recv (
                                router_socket, bottom, sizeof (bottom), 0)));
    TEST_ASSERT_EQUAL_INT (1, TEST_ASSERT_SUCCESS_ERRNO (zmq_recv (
                                router_socket, body, sizeof (body), 0)));

    //  Send invalid reply.
    TEST_ASSERT_EQUAL_INT (addr_size, TEST_ASSERT_SUCCESS_ERRNO (zmq_send (
                                        router_socket, addr, addr_size, 0)));

    //  Send valid reply.
    TEST_ASSERT_EQUAL_INT (
      addr_size, TEST_ASSERT_SUCCESS_ERRNO (
                   zmq_send (router_socket, addr, addr_size, ZMQ_SNDMORE)));
    TEST_ASSERT_EQUAL_INT (0, TEST_ASSERT_SUCCESS_ERRNO (zmq_send (
                                router_socket, bottom, 0, ZMQ_SNDMORE)));
    send_string_expect_success (router_socket, "b", 0);

    //  Check whether we've got the valid reply.
    recv_string_expect_success (req_socket, "b", 0);

    //  Tear down the wiring.
    test_context_socket_close (router_socket);
    test_context_socket_close (req_socket);
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_invalid_rep);
    return UNITY_END ();
}
