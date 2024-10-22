/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

SETUP_TEARDOWN_TESTCONTEXT

// DEBUG shouldn't be defined in sources as it will cause a redefined symbol
// error when it is defined in the build configuration. It appears that the
// intent here is to semi-permanently disable DEBUG tracing statements, so the
// implementation is changed to accommodate that intent.
//#define DEBUG 0
#define TRACE_ENABLED 0

void test_router_mandatory_hwm ()
{
    if (TRACE_ENABLED)
        fprintf (stderr, "Staring router mandatory HWM test ...\n");
    char my_endpoint[MAX_SOCKET_STRING];
    void *router = test_context_socket (ZMQ_ROUTER);

    // Configure router socket to mandatory routing and set HWM and linger
    int mandatory = 1;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (router, ZMQ_ROUTER_MANDATORY,
                                               &mandatory, sizeof (mandatory)));
    int sndhwm = 1;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (router, ZMQ_SNDHWM, &sndhwm, sizeof (sndhwm)));
    int linger = 1;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (router, ZMQ_LINGER, &linger, sizeof (linger)));

    bind_loopback_ipv4 (router, my_endpoint, sizeof my_endpoint);

    //  Create dealer called "X" and connect it to our router, configure HWM
    void *dealer = test_context_socket (ZMQ_DEALER);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (dealer, ZMQ_ROUTING_ID, "X", 1));
    int rcvhwm = 1;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (dealer, ZMQ_RCVHWM, &rcvhwm, sizeof (rcvhwm)));

    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (dealer, my_endpoint));

    //  Get message from dealer to know when connection is ready
    send_string_expect_success (dealer, "Hello", 0);
    recv_string_expect_success (router, "X", 0);

    int i;
    const int buf_size = 65536;
    const uint8_t buf[buf_size] = {0};
    // Send first batch of messages
    for (i = 0; i < 100000; ++i) {
        if (TRACE_ENABLED)
            fprintf (stderr, "Sending message %d ...\n", i);
        const int rc = zmq_send (router, "X", 1, ZMQ_DONTWAIT | ZMQ_SNDMORE);
        if (rc == -1 && zmq_errno () == EAGAIN)
            break;
        TEST_ASSERT_EQUAL_INT (1, rc);
        send_array_expect_success (router, buf, ZMQ_DONTWAIT);
    }
    // This should fail after one message but kernel buffering could
    // skew results
    TEST_ASSERT_LESS_THAN_INT (10, i);
    msleep (1000);
    // Send second batch of messages
    for (; i < 100000; ++i) {
        if (TRACE_ENABLED)
            fprintf (stderr, "Sending message %d (part 2) ...\n", i);
        const int rc = zmq_send (router, "X", 1, ZMQ_DONTWAIT | ZMQ_SNDMORE);
        if (rc == -1 && zmq_errno () == EAGAIN)
            break;
        TEST_ASSERT_EQUAL_INT (1, rc);
        send_array_expect_success (router, buf, ZMQ_DONTWAIT);
    }
    // This should fail after two messages but kernel buffering could
    // skew results
    TEST_ASSERT_LESS_THAN_INT (20, i);

    if (TRACE_ENABLED)
        fprintf (stderr, "Done sending messages.\n");

    test_context_socket_close (router);
    test_context_socket_close (dealer);
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_router_mandatory_hwm);
    return UNITY_END ();
}
