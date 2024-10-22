/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

SETUP_TEARDOWN_TESTCONTEXT

void test_stream_empty ()
{
    char my_endpoint[MAX_SOCKET_STRING];

    void *stream = test_context_socket (ZMQ_STREAM);
    void *dealer = test_context_socket (ZMQ_DEALER);

    bind_loopback_ipv4 (stream, my_endpoint, sizeof my_endpoint);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (dealer, my_endpoint));
    send_string_expect_success (dealer, "", 0);

    zmq_msg_t ident, empty;
    zmq_msg_init (&ident);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_recv (&ident, stream, 0));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_msg_init_data (&empty, (void *) "", 0, NULL, NULL));

    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_send (&ident, stream, ZMQ_SNDMORE));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&ident));

    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_send (&empty, stream, 0));

    //  This close used to fail with Bad Address
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&empty));

    test_context_socket_close_zero_linger (dealer);
    test_context_socket_close_zero_linger (stream);
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_stream_empty);
    return UNITY_END ();
}
