/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

SETUP_TEARDOWN_TESTCONTEXT

void test ()
{
    //  Create a publisher
    void *pub = test_context_socket (ZMQ_XPUB);

    int hwm = 2000;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (pub, ZMQ_SNDHWM, &hwm, 4));

    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (pub, "inproc://soname"));

    //  set pub socket options
    int wait = 1;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (pub, ZMQ_XPUB_NODROP, &wait, 4));

    //  Create a subscriber
    void *sub = test_context_socket (ZMQ_SUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sub, "inproc://soname"));

    //  Subscribe for all messages.
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (sub, ZMQ_SUBSCRIBE, "", 0));

    //  we must wait for the subscription to be processed here, otherwise some
    //  or all published messages might be lost
    recv_string_expect_success (pub, "\1", 0);

    int hwmlimit = hwm - 1;
    int send_count = 0;

    //  Send an empty message
    for (int i = 0; i < hwmlimit; i++) {
        TEST_ASSERT_SUCCESS_ERRNO (zmq_send (pub, NULL, 0, 0));
        send_count++;
    }

    int recv_count = 0;
    do {
        //  Receive the message in the subscriber
        int rc = zmq_recv (sub, NULL, 0, 0);
        if (rc == -1) {
            TEST_ASSERT_EQUAL_INT (EAGAIN, errno);
            break;
        }
        TEST_ASSERT_EQUAL_INT (0, rc);
        recv_count++;

        if (recv_count == 1) {
            const int sub_rcvtimeo = 250;
            TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
              sub, ZMQ_RCVTIMEO, &sub_rcvtimeo, sizeof (sub_rcvtimeo)));
        }

    } while (true);

    TEST_ASSERT_EQUAL_INT (send_count, recv_count);

    //  Now test real blocking behavior
    //  Set a timeout, default is infinite
    int timeout = 0;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (pub, ZMQ_SNDTIMEO, &timeout, 4));

    send_count = 0;
    recv_count = 0;
    hwmlimit = hwm;

    //  Send an empty message until we get an error, which must be EAGAIN
    while (zmq_send (pub, "", 0, 0) == 0)
        send_count++;
    TEST_ASSERT_EQUAL_INT (EAGAIN, errno);

    if (send_count > 0) {
        //  Receive first message with blocking
        TEST_ASSERT_SUCCESS_ERRNO (zmq_recv (sub, NULL, 0, 0));
        recv_count++;

        while (zmq_recv (sub, NULL, 0, ZMQ_DONTWAIT) == 0)
            recv_count++;
    }

    TEST_ASSERT_EQUAL_INT (send_count, recv_count);

    //  Clean up.
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
