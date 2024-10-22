/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

#include <unity.h>

void *sb;
void *sc;

void setUp ()
{
    setup_test_context ();

    sb = test_context_socket (ZMQ_CHANNEL);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (sb, "inproc://a"));

    sc = test_context_socket (ZMQ_CHANNEL);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc, "inproc://a"));
}

void tearDown ()
{
    test_context_socket_close (sc);
    test_context_socket_close (sb);

    teardown_test_context ();
}

void test_roundtrip ()
{
    send_string_expect_success (sb, "HELLO", 0);
    recv_string_expect_success (sc, "HELLO", 0);

    send_string_expect_success (sc, "WORLD", 0);
    recv_string_expect_success (sb, "WORLD", 0);
}

void test_sndmore_fails ()
{
    int rc = zmq_send (sc, "X", 1, ZMQ_SNDMORE);
    TEST_ASSERT_EQUAL_INT (-1, rc);
    TEST_ASSERT_EQUAL_INT (EINVAL, errno);
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_roundtrip);
    RUN_TEST (test_sndmore_fails);
    return UNITY_END ();
}
