/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

SETUP_TEARDOWN_TESTCONTEXT

void test ()
{
    //  First, create an intermediate device.
    void *xpub = test_context_socket (ZMQ_XPUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (xpub, "tipc://{5560,0,0}"));
    void *xsub = test_context_socket (ZMQ_XSUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (xsub, "tipc://{5561,0,0}"));

    //  Create a publisher.
    void *pub = test_context_socket (ZMQ_PUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (pub, "tipc://{5561,0}@0.0.0"));

    //  Create a subscriber.
    void *sub = test_context_socket (ZMQ_SUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sub, "tipc://{5560,0}@0.0.0"));

    // TODO the remainder of this method is duplicated with test_sub_forward

    //  Subscribe for all messages.
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (sub, ZMQ_SUBSCRIBE, "", 0));

    //  Pass the subscription upstream through the device
    char buff[32];
    int size;
    TEST_ASSERT_SUCCESS_ERRNO (size = zmq_recv (xpub, buff, sizeof (buff), 0));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_send (xsub, buff, size, 0));

    //  Wait a bit till the subscription gets to the publisher
    msleep (SETTLE_TIME);

    //  Send an empty message
    send_string_expect_success (pub, "", 0);

    //  Pass the message downstream through the device
    TEST_ASSERT_SUCCESS_ERRNO (size = zmq_recv (xsub, buff, sizeof (buff), 0));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_send (xpub, buff, size, 0));

    //  Receive the message in the subscriber
    recv_string_expect_success (sub, "", 0);

    //  Clean up.
    test_context_socket_close (xpub);
    test_context_socket_close (xsub);
    test_context_socket_close (pub);
    test_context_socket_close (sub);
}

int main ()
{
    if (!is_tipc_available ()) {
        printf ("TIPC environment unavailable, skipping test\n");
        return 77;
    }

    UNITY_BEGIN ();
    RUN_TEST (test);
    return UNITY_END ();
}
