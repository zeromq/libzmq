/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

#include <string.h>

SETUP_TEARDOWN_TESTCONTEXT

void test_getsockopt_memset ()
{
    int64_t more;
    size_t more_size = sizeof (more);

    void *sb = test_context_socket (ZMQ_PUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (sb, "inproc://a"));

    void *sc = test_context_socket (ZMQ_SUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc, "inproc://a"));

    memset (&more, 0xFF, sizeof (int64_t));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (sc, ZMQ_RCVMORE, &more, &more_size));
    TEST_ASSERT_EQUAL_INT (sizeof (int), more_size);
    TEST_ASSERT_EQUAL_INT (0, more);

    // Cleanup
    test_context_socket_close (sc);
    test_context_socket_close (sb);
}

int main (void)
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_getsockopt_memset);
    return UNITY_END ();
}
