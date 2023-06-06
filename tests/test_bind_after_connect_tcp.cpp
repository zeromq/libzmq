/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

SETUP_TEARDOWN_TESTCONTEXT

void test_x ()
{
    void *sb = test_context_socket (ZMQ_DEALER);
    void *sc = test_context_socket (ZMQ_DEALER);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc, ENDPOINT_3));

    send_string_expect_success (sc, "foobar", 0);
    send_string_expect_success (sc, "baz", 0);
    send_string_expect_success (sc, "buzz", 0);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (sb, ENDPOINT_3));

    recv_string_expect_success (sb, "foobar", 0);
    recv_string_expect_success (sb, "baz", 0);
    recv_string_expect_success (sb, "buzz", 0);

    test_context_socket_close (sc);
    test_context_socket_close (sb);
}

int main (void)
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_x);
    return UNITY_END ();
}
