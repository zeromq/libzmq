/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

SETUP_TEARDOWN_TESTCONTEXT

static void do_bind_and_verify (void *s_, const char *endpoint_)
{
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (s_, endpoint_));
    char reported[255];
    size_t size = 255;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (s_, ZMQ_LAST_ENDPOINT, reported, &size));
    TEST_ASSERT_EQUAL_STRING (endpoint_, reported);
}

void test_last_endpoint ()
{
    void *sb = test_context_socket (ZMQ_ROUTER);
    int val = 0;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sb, ZMQ_LINGER, &val, sizeof (val)));

    do_bind_and_verify (sb, ENDPOINT_1);
    do_bind_and_verify (sb, ENDPOINT_2);

    test_context_socket_close (sb);
}

int main (void)
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_last_endpoint);
    return UNITY_END ();
}
