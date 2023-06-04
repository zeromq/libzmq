/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

SETUP_TEARDOWN_TESTCONTEXT

void test_roundtrip ()
{
    char endpoint1[MAX_SOCKET_STRING];
    char endpoint2[MAX_SOCKET_STRING];

    //  Create a req/rep device.
    void *dealer = test_context_socket (ZMQ_DEALER);
    bind_loopback_ipv4 (dealer, endpoint1, sizeof (endpoint1));

    void *router = test_context_socket (ZMQ_ROUTER);
    bind_loopback_ipv4 (router, endpoint2, sizeof (endpoint2));

    //  Create a worker.
    void *rep = test_context_socket (ZMQ_REP);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (rep, endpoint1));

    //  Create a client.
    void *req = test_context_socket (ZMQ_REQ);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (req, endpoint2));

    //  Send a request.
    send_string_expect_success (req, "ABC", ZMQ_SNDMORE);
    send_string_expect_success (req, "DEF", 0);

    //  Pass the request through the device.
    for (int i = 0; i != 4; i++) {
        zmq_msg_t msg;
        TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init (&msg));
        TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_recv (&msg, router, 0));
        int rcvmore;
        size_t sz = sizeof (rcvmore);
        TEST_ASSERT_SUCCESS_ERRNO (
          zmq_getsockopt (router, ZMQ_RCVMORE, &rcvmore, &sz));
        TEST_ASSERT_SUCCESS_ERRNO (
          zmq_msg_send (&msg, dealer, rcvmore ? ZMQ_SNDMORE : 0));
    }

    //  Receive the request.
    recv_string_expect_success (rep, "ABC", 0);
    int rcvmore;
    size_t sz = sizeof (rcvmore);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (rep, ZMQ_RCVMORE, &rcvmore, &sz));
    TEST_ASSERT_TRUE (rcvmore);
    recv_string_expect_success (rep, "DEF", 0);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (rep, ZMQ_RCVMORE, &rcvmore, &sz));
    TEST_ASSERT_FALSE (rcvmore);

    //  Send the reply.
    send_string_expect_success (rep, "GHI", ZMQ_SNDMORE);
    send_string_expect_success (rep, "JKL", 0);

    //  Pass the reply through the device.
    for (int i = 0; i != 4; i++) {
        zmq_msg_t msg;
        TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init (&msg));
        TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_recv (&msg, dealer, 0));
        int rcvmore;
        size_t sz = sizeof (rcvmore);
        TEST_ASSERT_SUCCESS_ERRNO (
          zmq_getsockopt (dealer, ZMQ_RCVMORE, &rcvmore, &sz));
        TEST_ASSERT_SUCCESS_ERRNO (
          zmq_msg_send (&msg, router, rcvmore ? ZMQ_SNDMORE : 0));
    }

    //  Receive the reply.
    recv_string_expect_success (req, "GHI", 0);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (req, ZMQ_RCVMORE, &rcvmore, &sz));
    TEST_ASSERT_TRUE (rcvmore);
    recv_string_expect_success (req, "JKL", 0);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (req, ZMQ_RCVMORE, &rcvmore, &sz));
    TEST_ASSERT_FALSE (rcvmore);

    //  Clean up.
    test_context_socket_close (req);
    test_context_socket_close (rep);
    test_context_socket_close (router);
    test_context_socket_close (dealer);
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_roundtrip);
    return UNITY_END ();
}
