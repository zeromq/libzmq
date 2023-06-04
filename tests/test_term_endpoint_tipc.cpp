/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

SETUP_TEARDOWN_TESTCONTEXT

const char ep[] = "tipc://{5560,0,0}";
const char name[] = "tipc://{5560,0}@0.0.0";

void test_term_endpoint_unbind_tipc ()
{
    if (!is_tipc_available ()) {
        TEST_IGNORE_MESSAGE ("TIPC environment unavailable, skipping test\n");
    }

    //  Create infrastructure.
    void *push = test_context_socket (ZMQ_PUSH);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (push, ep));
    void *pull = test_context_socket (ZMQ_PULL);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (pull, name));

    //  Pass one message through to ensure the connection is established.
    send_string_expect_success (push, "ABC", 0);
    recv_string_expect_success (pull, "ABC", 0);

    // Unbind the lisnening endpoint
    TEST_ASSERT_SUCCESS_ERRNO (zmq_unbind (push, ep));

    // Let events some time
    msleep (SETTLE_TIME);

    //  Check that sending would block (there's no outbound connection).
    TEST_ASSERT_FAILURE_ERRNO (EAGAIN, zmq_send (push, "ABC", 3, ZMQ_DONTWAIT));

    //  Clean up.
    test_context_socket_close (pull);
    test_context_socket_close (push);
}

void test_term_endpoint_disconnect_tipc ()
{
    if (!is_tipc_available ()) {
        TEST_IGNORE_MESSAGE ("TIPC environment unavailable, skipping test\n");
    }

    //  Create infrastructure.
    void *push = test_context_socket (ZMQ_PUSH);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (push, name));
    void *pull = test_context_socket (ZMQ_PULL);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (pull, ep));

    //  Pass one message through to ensure the connection is established.
    send_string_expect_success (push, "ABC", 0);
    recv_string_expect_success (pull, "ABC", 0);

    // Disconnect the bound endpoint
    TEST_ASSERT_SUCCESS_ERRNO (zmq_disconnect (push, name));

    msleep (SETTLE_TIME);

    //  Check that sending would block (there's no inbound connections).
    TEST_ASSERT_FAILURE_ERRNO (EAGAIN, zmq_send (push, "ABC", 3, ZMQ_DONTWAIT));

    //  Clean up.
    test_context_socket_close (pull);
    test_context_socket_close (push);
}

int main (void)
{
    UNITY_BEGIN ();
    RUN_TEST (test_term_endpoint_unbind_tipc);
    RUN_TEST (test_term_endpoint_disconnect_tipc);
    return UNITY_END ();
}
