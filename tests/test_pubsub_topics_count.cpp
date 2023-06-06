/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"
#include <string.h>

SETUP_TEARDOWN_TESTCONTEXT


void settle_subscriptions (void *skt)
{
    //  To kick the application thread, do a dummy getsockopt - users here
    //  should use the monitor and the other sockets in a poll.
    unsigned long int dummy;
    size_t dummy_size = sizeof (dummy);
    msleep (SETTLE_TIME);
    zmq_getsockopt (skt, ZMQ_EVENTS, &dummy, &dummy_size);
}

int get_subscription_count (void *skt)
{
    int num_subs = 0;
    size_t num_subs_len = sizeof (num_subs);

    settle_subscriptions (skt);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (skt, ZMQ_TOPICS_COUNT, &num_subs, &num_subs_len));

    return num_subs;
}

void test_independent_topic_prefixes ()
{
    //  Create a publisher
    void *publisher = test_context_socket (ZMQ_PUB);
    char my_endpoint[MAX_SOCKET_STRING];

    //  Bind publisher
    test_bind (publisher, "inproc://soname", my_endpoint, MAX_SOCKET_STRING);

    //  Create a subscriber
    void *subscriber = test_context_socket (ZMQ_SUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (subscriber, my_endpoint));

    //  Subscribe to 3 topics
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      subscriber, ZMQ_SUBSCRIBE, "topicprefix1", strlen ("topicprefix1")));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      subscriber, ZMQ_SUBSCRIBE, "topicprefix2", strlen ("topicprefix2")));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      subscriber, ZMQ_SUBSCRIBE, "topicprefix3", strlen ("topicprefix3")));
    TEST_ASSERT_EQUAL_INT (get_subscription_count (subscriber), 3);
    TEST_ASSERT_EQUAL_INT (get_subscription_count (publisher), 3);

    // Remove first subscription and check subscriptions went 3 -> 2
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      subscriber, ZMQ_UNSUBSCRIBE, "topicprefix3", strlen ("topicprefix3")));
    TEST_ASSERT_EQUAL_INT (get_subscription_count (subscriber), 2);
    TEST_ASSERT_EQUAL_INT (get_subscription_count (publisher), 2);

    // Remove other 2 subscriptions and check we're back to 0 subscriptions
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      subscriber, ZMQ_UNSUBSCRIBE, "topicprefix1", strlen ("topicprefix1")));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      subscriber, ZMQ_UNSUBSCRIBE, "topicprefix2", strlen ("topicprefix2")));
    TEST_ASSERT_EQUAL_INT (get_subscription_count (subscriber), 0);
    TEST_ASSERT_EQUAL_INT (get_subscription_count (publisher), 0);

    //  Clean up.
    test_context_socket_close (publisher);
    test_context_socket_close (subscriber);
}

void test_nested_topic_prefixes ()
{
    //  Create a publisher
    void *publisher = test_context_socket (ZMQ_PUB);
    char my_endpoint[MAX_SOCKET_STRING];

    //  Bind publisher
    test_bind (publisher, "inproc://soname", my_endpoint, MAX_SOCKET_STRING);

    //  Create a subscriber
    void *subscriber = test_context_socket (ZMQ_SUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (subscriber, my_endpoint));

    //  Subscribe to 3 (nested) topics
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (subscriber, ZMQ_SUBSCRIBE, "a", strlen ("a")));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (subscriber, ZMQ_SUBSCRIBE, "ab", strlen ("ab")));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (subscriber, ZMQ_SUBSCRIBE, "abc", strlen ("abc")));

    // Even if the subscriptions are nested one into the other, the number of subscriptions
    // received on the subscriber/publisher socket will be 3:
    TEST_ASSERT_EQUAL_INT (get_subscription_count (subscriber), 3);
    TEST_ASSERT_EQUAL_INT (get_subscription_count (publisher), 3);

    //  Subscribe to other 3 (nested) topics
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (subscriber, ZMQ_SUBSCRIBE, "xyz", strlen ("xyz")));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (subscriber, ZMQ_SUBSCRIBE, "xy", strlen ("xy")));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (subscriber, ZMQ_SUBSCRIBE, "x", strlen ("x")));

    TEST_ASSERT_EQUAL_INT (get_subscription_count (subscriber), 6);
    TEST_ASSERT_EQUAL_INT (get_subscription_count (publisher), 6);

    //  Clean up.
    test_context_socket_close (publisher);
    test_context_socket_close (subscriber);
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_independent_topic_prefixes);
    RUN_TEST (test_nested_topic_prefixes);
    return UNITY_END ();
}
