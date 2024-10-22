/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

SETUP_TEARDOWN_TESTCONTEXT

void test_rebind_ipc ()
{
    char my_endpoint[MAX_SOCKET_STRING];
    make_random_ipc_endpoint (my_endpoint);

    void *sb0 = test_context_socket (ZMQ_PUSH);
    void *sb1 = test_context_socket (ZMQ_PUSH);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (sb0, my_endpoint));

    void *sc = test_context_socket (ZMQ_PULL);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc, my_endpoint));

    send_string_expect_success (sb0, "42", 0);
    recv_string_expect_success (sc, "42", 0);

    test_context_socket_close (sb0);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (sb1, my_endpoint));

    send_string_expect_success (sb1, "42", 0);
    recv_string_expect_success (sc, "42", 0);

    test_context_socket_close (sc);
    test_context_socket_close (sb1);
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_rebind_ipc);
    return UNITY_END ();
}
