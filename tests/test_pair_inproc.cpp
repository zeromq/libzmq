/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

#include <unity.h>

void *sb;
void *sc;

void setUp ()
{
    setup_test_context ();

    sb = test_context_socket (ZMQ_PAIR);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (sb, "inproc://a"));

    sc = test_context_socket (ZMQ_PAIR);
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
    bounce (sb, sc);
}

// TODO it appears that this has nothing to do with pair or inproc, and belongs somewhere else
void test_zmq_send_const ()
{
    TEST_ASSERT_EQUAL_INT (3, TEST_ASSERT_SUCCESS_ERRNO (
                                zmq_send_const (sb, "foo", 3, ZMQ_SNDMORE)));
    TEST_ASSERT_EQUAL_INT (
      6, TEST_ASSERT_SUCCESS_ERRNO (zmq_send_const (sb, "foobar", 6, 0)));

    recv_string_expect_success (sc, "foo", 0);
    recv_string_expect_success (sc, "foobar", 0);
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_roundtrip);
    RUN_TEST (test_zmq_send_const);
    return UNITY_END ();
}
