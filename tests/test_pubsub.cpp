/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

SETUP_TEARDOWN_TESTCONTEXT

void test (const char *address)
{
    //  Create a publisher
    void *publisher = test_context_socket (ZMQ_PUB);
    char my_endpoint[MAX_SOCKET_STRING];

    //  Bind publisher
    test_bind (publisher, address, my_endpoint, MAX_SOCKET_STRING);

    //  Create a subscriber
    void *subscriber = test_context_socket (ZMQ_SUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (subscriber, my_endpoint));

    //  Subscribe to all messages.
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (subscriber, ZMQ_SUBSCRIBE, "", 0));

    //  Wait a bit till the subscription gets to the publisher
    msleep (SETTLE_TIME);

    //  Send an empty message
    send_string_expect_success (publisher, "test", 0);

    //  Receive the message in the subscriber
    recv_string_expect_success (subscriber, "test", 0);

    //  Clean up.
    test_context_socket_close (publisher);
    test_context_socket_close (subscriber);
}

void test_norm ()
{
#if defined ZMQ_HAVE_NORM
    test (
      "norm://224.0.1.20:6210"); // IANA: experiment.mcast.net (any private experiment)
#else
    TEST_IGNORE_MESSAGE ("libzmq without NORM, ignoring test");
#endif
}

void test_pgm ()
{
#if defined ZMQ_HAVE_OPENPGM
    test (
      "pgm://10.0.0.104;224.0.1.20:6211"); // IANA: experiment.mcast.net (any private experiment)
#else
    TEST_IGNORE_MESSAGE ("libzmq without OpenPGM, ignoring test");
#endif
}

void test_epgm ()
{
#if defined ZMQ_HAVE_OPENPGM
    test (
      "epgm://10.0.0.104;224.0.1.20:6212"); // IANA: experiment.mcast.net (any private experiment)
#else
    TEST_IGNORE_MESSAGE ("libzmq without OpenPGM, ignoring test");
#endif
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_norm);
    RUN_TEST (test_pgm);
    RUN_TEST (test_epgm);
    return UNITY_END ();
}
