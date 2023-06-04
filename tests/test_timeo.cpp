/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

SETUP_TEARDOWN_TESTCONTEXT

void test_timeo ()
{
    void *frontend = test_context_socket (ZMQ_DEALER);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (frontend, "inproc://timeout_test"));

    //  Receive on disconnected socket returns immediately
    char buffer[32];
    TEST_ASSERT_FAILURE_ERRNO (EAGAIN,
                               zmq_recv (frontend, buffer, 32, ZMQ_DONTWAIT));


    //  Check whether receive timeout is honored
    const int timeout = 250;
    const int jitter = 50;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (frontend, ZMQ_RCVTIMEO, &timeout, sizeof (int)));

    void *stopwatch = zmq_stopwatch_start ();
    TEST_ASSERT_FAILURE_ERRNO (EAGAIN, zmq_recv (frontend, buffer, 32, 0));
    unsigned int elapsed = zmq_stopwatch_stop (stopwatch) / 1000;
    TEST_ASSERT_GREATER_THAN_INT (timeout - jitter, elapsed);
    if (elapsed >= timeout + jitter) {
        // we cannot assert this on a non-RT system
        fprintf (stderr,
                 "zmq_recv took quite long, with a timeout of %i ms, it took "
                 "actually %i ms\n",
                 timeout, elapsed);
    }

    //  Check that normal message flow works as expected
    void *backend = test_context_socket (ZMQ_DEALER);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (backend, "inproc://timeout_test"));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (backend, ZMQ_SNDTIMEO, &timeout, sizeof (int)));

    send_string_expect_success (backend, "Hello", 0);
    recv_string_expect_success (frontend, "Hello", 0);

    //  Clean-up
    test_context_socket_close (backend);
    test_context_socket_close (frontend);
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_timeo);
    return UNITY_END ();
}
