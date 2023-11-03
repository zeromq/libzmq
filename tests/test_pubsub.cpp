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

    //  Send three messages
    send_string_expect_success (publisher, "test", 0);
    send_string_expect_success (publisher, "test", 0);
    send_string_expect_success (publisher, "test", 0);

    //  Receive the messages
    recv_string_expect_success (subscriber, "test", 0);
    recv_string_expect_success (subscriber, "test", 0);
    recv_string_expect_success (subscriber, "test", 0);

    //  Clean up.
    test_context_socket_close (publisher);
    test_context_socket_close (subscriber);
}

void test_norm ()
{
#if defined ZMQ_HAVE_NORM
    test ("norm://224.1.2.3:5556");
#else
    TEST_IGNORE_MESSAGE ("libzmq without NORM, ignoring test");
#endif
}

void test_OpenPGM ()
{
#if defined ZMQ_HAVE_OPENPGM
#if defined(ZMQ_HAVE_WINDOWS)
#define NETWORK_ADAPTER "127.0.0.1"
#else
#define NETWORK_ADAPTER "eth0"
#endif
    test ("epgm://" NETWORK_ADAPTER ";224.0.0.1:23130");
    test ("pgm://" NETWORK_ADAPTER ";224.0.0.1:23130");
#else
    TEST_IGNORE_MESSAGE ("libzmq without OpenPGM, ignoring test");
#endif
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_norm);
    RUN_TEST (test_OpenPGM);
    return UNITY_END ();
}
