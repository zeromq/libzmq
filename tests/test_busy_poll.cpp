/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

SETUP_TEARDOWN_TESTCONTEXT

void test_busy_poll ()
{
    //  Create a socket
    void *socket = test_context_socket (ZMQ_DEALER);

    //  set socket ZMQ_BUSY_POLL options
    int busy_poll = 1;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (socket, ZMQ_BUSY_POLL, &busy_poll, sizeof (int)));

    //  bind socket
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (socket, "tcp://127.0.0.1:*"));

    //  Clean up.
    test_context_socket_close (socket);
}

int main ()
{
    setup_test_environment ();
    UNITY_BEGIN ();
    RUN_TEST (test_busy_poll);
    return UNITY_END ();
}
