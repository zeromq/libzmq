/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

SETUP_TEARDOWN_TESTCONTEXT

const char bind_address[] = "tcp://127.0.0.1:*";
char connect_address[MAX_SOCKET_STRING];

// 245 chars + 10 chars for subscribe command = 255 chars
const char short_topic[] =
  "ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOPABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP"
  "ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOPABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP"
  "ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOPABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP"
  "ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOPABCDEFGHIJKLMNOPABCDE";

// 246 chars + 10 chars for subscribe command = 256 chars
const char long_topic[] =
  "ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOPABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP"
  "ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOPABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP"
  "ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOPABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP"
  "ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOPABCDEFGHIJKLMNOPABCDEF";


template <size_t SIZE>
void test_subscribe_cancel (void *xpub, void *sub, const char (&topic)[SIZE])
{
    // Ignore '\0' terminating the topic string.
    const size_t topic_len = SIZE - 1;

    //  Subscribe for topic
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sub, ZMQ_SUBSCRIBE, topic, topic_len));

    // Allow receiving more than the expected number of bytes
    char buffer[topic_len + 5];

    // Receive subscription
    int rc =
      TEST_ASSERT_SUCCESS_ERRNO (zmq_recv (xpub, buffer, sizeof (buffer), 0));
    TEST_ASSERT_EQUAL_INT (topic_len + 1, rc);
    TEST_ASSERT_EQUAL_UINT8 (1, buffer[0]);
    TEST_ASSERT_EQUAL_UINT8_ARRAY (topic, buffer + 1, topic_len);

    // Unsubscribe from topic
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sub, ZMQ_UNSUBSCRIBE, topic, topic_len));

    // Receive unsubscription
    rc =
      TEST_ASSERT_SUCCESS_ERRNO (zmq_recv (xpub, buffer, sizeof (buffer), 0));
    TEST_ASSERT_EQUAL_INT (topic_len + 1, rc);
    TEST_ASSERT_EQUAL_UINT8 (0, buffer[0]);
    TEST_ASSERT_EQUAL_UINT8_ARRAY (topic, buffer + 1, topic_len);
}

void test_xpub_subscribe_long_topic ()
{
    void *xpub = test_context_socket (ZMQ_XPUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (xpub, bind_address));
    size_t len = MAX_SOCKET_STRING;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (xpub, ZMQ_LAST_ENDPOINT, connect_address, &len));

    void *sub = test_context_socket (ZMQ_SUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sub, connect_address));

    test_subscribe_cancel (xpub, sub, short_topic);
    test_subscribe_cancel (xpub, sub, long_topic);

    //  Clean up.
    test_context_socket_close (xpub);
    test_context_socket_close (sub);
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_xpub_subscribe_long_topic);

    return UNITY_END ();
}
