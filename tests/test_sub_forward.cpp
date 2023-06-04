/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

SETUP_TEARDOWN_TESTCONTEXT

void test ()
{
    char endpoint1[MAX_SOCKET_STRING];
    char endpoint2[MAX_SOCKET_STRING];

    //  First, create an intermediate device
    void *xpub = test_context_socket (ZMQ_XPUB);
    bind_loopback_ipv4 (xpub, endpoint1, sizeof (endpoint1));

    void *xsub = test_context_socket (ZMQ_XSUB);
    bind_loopback_ipv4 (xsub, endpoint2, sizeof (endpoint2));

    //  Create a publisher
    void *pub = test_context_socket (ZMQ_PUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (pub, endpoint2));

    //  Create a subscriber
    void *sub = test_context_socket (ZMQ_SUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sub, endpoint1));

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
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test);
    return UNITY_END ();
}
