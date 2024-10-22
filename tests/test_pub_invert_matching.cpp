/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

#include <string.h>

SETUP_TEARDOWN_TESTCONTEXT

void test ()
{
    //  Create a publisher
    void *pub = test_context_socket (ZMQ_PUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (pub, "inproc://soname"));

    //  Create two subscribers
    void *sub1 = test_context_socket (ZMQ_SUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sub1, "inproc://soname"));

    void *sub2 = test_context_socket (ZMQ_SUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sub2, "inproc://soname"));

    //  Subscribe pub1 to one prefix
    //  and pub2 to another prefix.
    const char prefi_x1[] = "prefix1";
    const char prefi_x2[] = "p2";

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sub1, ZMQ_SUBSCRIBE, prefi_x1, strlen (prefi_x1)));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sub2, ZMQ_SUBSCRIBE, prefi_x2, strlen (prefi_x2)));

    //  Send a message with the first prefix
    send_string_expect_success (pub, prefi_x1, 0);
    msleep (SETTLE_TIME);

    //  sub1 should receive it, but not sub2
    recv_string_expect_success (sub1, prefi_x1, ZMQ_DONTWAIT);

    TEST_ASSERT_FAILURE_ERRNO (EAGAIN, zmq_recv (sub2, NULL, 0, ZMQ_DONTWAIT));

    //  Send a message with the second prefix
    send_string_expect_success (pub, prefi_x2, 0);
    msleep (SETTLE_TIME);

    //  sub2 should receive it, but not sub1
    recv_string_expect_success (sub2, prefi_x2, ZMQ_DONTWAIT);

    TEST_ASSERT_FAILURE_ERRNO (EAGAIN, zmq_recv (sub1, NULL, 0, ZMQ_DONTWAIT));

    //  Now invert the matching
    int invert = 1;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (pub, ZMQ_INVERT_MATCHING, &invert, sizeof (invert)));

    //  ... on both sides, otherwise the SUB socket will filter the messages out
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sub1, ZMQ_INVERT_MATCHING, &invert, sizeof (invert)));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sub2, ZMQ_INVERT_MATCHING, &invert, sizeof (invert)));

    //  Send a message with the first prefix
    send_string_expect_success (pub, prefi_x1, 0);
    msleep (SETTLE_TIME);

    //  sub2 should receive it, but not sub1
    recv_string_expect_success (sub2, prefi_x1, ZMQ_DONTWAIT);

    TEST_ASSERT_FAILURE_ERRNO (EAGAIN, zmq_recv (sub1, NULL, 0, ZMQ_DONTWAIT));

    //  Send a message with the second prefix
    send_string_expect_success (pub, prefi_x2, 0);
    msleep (SETTLE_TIME);

    //  sub1 should receive it, but not sub2
    recv_string_expect_success (sub1, prefi_x2, ZMQ_DONTWAIT);

    TEST_ASSERT_FAILURE_ERRNO (EAGAIN, zmq_recv (sub2, NULL, 0, ZMQ_DONTWAIT));

    //  Clean up.
    test_context_socket_close (pub);
    test_context_socket_close (sub1);
    test_context_socket_close (sub2);
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test);
    return UNITY_END ();
}
