/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

#include <string.h>

SETUP_TEARDOWN_TESTCONTEXT

void ffn (void *data_, void *hint_)
{
    // Signal that ffn has been called by writing "freed" to hint
    (void) data_; //  Suppress 'unused' warnings at compile time
    memcpy (hint_, (void *) "freed", 5);
}

void test_msg_init_ffn ()
{
    //  Create the infrastructure
    char my_endpoint[MAX_SOCKET_STRING];

    void *router = test_context_socket (ZMQ_ROUTER);
    bind_loopback_ipv4 (router, my_endpoint, sizeof my_endpoint);

    void *dealer = test_context_socket (ZMQ_DEALER);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (dealer, my_endpoint));

    // Test that creating and closing a message triggers ffn
    zmq_msg_t msg;
    char hint[5];
    char data[255];
    memset (data, 0, 255);
    memcpy (data, (void *) "data", 4);
    memcpy (hint, (void *) "hint", 4);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_msg_init_data (&msg, (void *) data, 255, ffn, (void *) hint));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg));

    msleep (SETTLE_TIME);
    TEST_ASSERT_EQUAL_STRING_LEN ("freed", hint, 5);
    memcpy (hint, (void *) "hint", 4);

    // Making and closing a copy triggers ffn
    zmq_msg_t msg2;
    zmq_msg_init (&msg2);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_msg_init_data (&msg, (void *) data, 255, ffn, (void *) hint));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_copy (&msg2, &msg));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg2));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg));

    msleep (SETTLE_TIME);
    TEST_ASSERT_EQUAL_STRING_LEN ("freed", hint, 5);
    memcpy (hint, (void *) "hint", 4);

    // Test that sending a message triggers ffn
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_msg_init_data (&msg, (void *) data, 255, ffn, (void *) hint));

    zmq_msg_send (&msg, dealer, 0);
    char buf[255];
    TEST_ASSERT_SUCCESS_ERRNO (zmq_recv (router, buf, 255, 0));
    TEST_ASSERT_EQUAL_INT (255, zmq_recv (router, buf, 255, 0));
    TEST_ASSERT_EQUAL_STRING_LEN (data, buf, 4);

    msleep (SETTLE_TIME);
    TEST_ASSERT_EQUAL_STRING_LEN ("freed", hint, 5);
    memcpy (hint, (void *) "hint", 4);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg));

    // Sending a copy of a message triggers ffn
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init (&msg2));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_msg_init_data (&msg, (void *) data, 255, ffn, (void *) hint));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_copy (&msg2, &msg));

    zmq_msg_send (&msg, dealer, 0);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_recv (router, buf, 255, 0));
    TEST_ASSERT_EQUAL_INT (255, zmq_recv (router, buf, 255, 0));
    TEST_ASSERT_EQUAL_STRING_LEN (data, buf, 4);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg2));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg));

    msleep (SETTLE_TIME);
    TEST_ASSERT_EQUAL_STRING_LEN ("freed", hint, 5);

    //  Deallocate the infrastructure.
    test_context_socket_close (router);
    test_context_socket_close (dealer);
}

int main (void)
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_msg_init_ffn);
    return UNITY_END ();
}
