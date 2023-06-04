/* SPDX-License-Identifier: MPL-2.0 */

#include <stdio.h>
#include "testutil.hpp"

#include "testutil_unity.hpp"

SETUP_TEARDOWN_TESTCONTEXT

void test_router_mandatory_tipc ()
{
    if (!is_tipc_available ()) {
        TEST_IGNORE_MESSAGE ("TIPC environment unavailable, skipping test");
    }

    // Creating the first socket.
    void *sa = test_context_socket (ZMQ_ROUTER);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (sa, "tipc://{15560,0,0}"));

    // Sending a message to an unknown peer with the default setting
    send_string_expect_success (sa, "UNKNOWN", ZMQ_SNDMORE);
    send_string_expect_success (sa, "DATA", 0);

    int mandatory = 1;

    // Set mandatory routing on socket
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (sa, ZMQ_ROUTER_MANDATORY,
                                               &mandatory, sizeof (mandatory)));

    // Send a message and check that it fails
    TEST_ASSERT_FAILURE_ERRNO (
      EHOSTUNREACH, zmq_send (sa, "UNKNOWN", 7, ZMQ_SNDMORE | ZMQ_DONTWAIT));

    test_context_socket_close (sa);
}

int main (void)
{
    UNITY_BEGIN ();
    RUN_TEST (test_router_mandatory_tipc);
    return UNITY_END ();
}
