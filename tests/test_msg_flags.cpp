/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

SETUP_TEARDOWN_TESTCONTEXT

void test_more ()
{
    //  Create the infrastructure
    void *sb = test_context_socket (ZMQ_ROUTER);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (sb, "inproc://a"));

    void *sc = test_context_socket (ZMQ_DEALER);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc, "inproc://a"));

    //  Send 2-part message.
    send_string_expect_success (sc, "A", ZMQ_SNDMORE);
    send_string_expect_success (sc, "B", 0);

    //  Routing id comes first.
    zmq_msg_t msg;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init (&msg));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_recv (&msg, sb, 0));
    TEST_ASSERT_EQUAL_INT (1, TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_more (&msg)));

    //  Then the first part of the message body.
    TEST_ASSERT_EQUAL_INT (
      1, TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_recv (&msg, sb, 0)));
    TEST_ASSERT_EQUAL_INT (1, TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_more (&msg)));

    //  And finally, the second part of the message body.
    TEST_ASSERT_EQUAL_INT (
      1, TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_recv (&msg, sb, 0)));
    TEST_ASSERT_EQUAL_INT (0, TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_more (&msg)));

    //  Deallocate the infrastructure.
    test_context_socket_close (sc);
    test_context_socket_close (sb);
}

void test_shared_refcounted ()
{
    // Test ZMQ_SHARED property (case 1, refcounted messages)
    zmq_msg_t msg_a;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_msg_init_size (&msg_a, 1024)); // large enough to be a type_lmsg

    // Message is not shared
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_get (&msg_a, ZMQ_SHARED));

    zmq_msg_t msg_b;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init (&msg_b));

    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_copy (&msg_b, &msg_a));

    // Message is now shared
    TEST_ASSERT_EQUAL_INT (
      1, TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_get (&msg_b, ZMQ_SHARED)));

    // cleanup
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg_a));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg_b));
}

void test_shared_const ()
{
    zmq_msg_t msg_a;
    // Test ZMQ_SHARED property (case 2, constant data messages)
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_msg_init_data (&msg_a, (void *) "TEST", 5, 0, 0));

    // Message reports as shared
    TEST_ASSERT_EQUAL_INT (
      1, TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_get (&msg_a, ZMQ_SHARED)));

    // cleanup
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg_a));
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_more);
    RUN_TEST (test_shared_refcounted);
    RUN_TEST (test_shared_const);
    return UNITY_END ();
}
