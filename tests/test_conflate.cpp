/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

SETUP_TEARDOWN_TESTCONTEXT

void test_conflate ()
{
    char my_endpoint[MAX_SOCKET_STRING];

    int rc;

    void *s_in = test_context_socket (ZMQ_PULL);

    int conflate = 1;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (s_in, ZMQ_CONFLATE, &conflate, sizeof (conflate)));
    bind_loopback_ipv4 (s_in, my_endpoint, sizeof my_endpoint);

    void *s_out = test_context_socket (ZMQ_PUSH);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (s_out, my_endpoint));

    int message_count = 20;
    for (int j = 0; j < message_count; ++j) {
        TEST_ASSERT_SUCCESS_ERRNO (
          zmq_send (s_out, (void *) &j, sizeof (int), 0));
    }
    msleep (SETTLE_TIME);

    int payload_recved = 0;
    rc = TEST_ASSERT_SUCCESS_ERRNO (
      zmq_recv (s_in, (void *) &payload_recved, sizeof (int), 0));
    TEST_ASSERT_GREATER_THAN_INT (0, rc);
    TEST_ASSERT_EQUAL_INT (message_count - 1, payload_recved);

    test_context_socket_close (s_in);
    test_context_socket_close (s_out);
}

int main (int, char *[])
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_conflate);
    return UNITY_END ();
}
