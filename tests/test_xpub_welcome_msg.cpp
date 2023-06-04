/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

SETUP_TEARDOWN_TESTCONTEXT

void test ()
{
    //  Create a publisher
    void *pub = test_context_socket (ZMQ_XPUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (pub, "inproc://soname"));

    //  set pub socket options
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (pub, ZMQ_XPUB_WELCOME_MSG, "W", 1));

    //  Create a subscriber
    void *sub = test_context_socket (ZMQ_SUB);

    // Subscribe to the welcome message
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (sub, ZMQ_SUBSCRIBE, "W", 1));

    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sub, "inproc://soname"));

    const uint8_t buffer[2] = {1, 'W'};

    // Receive the welcome subscription
    recv_array_expect_success (pub, buffer, 0);

    // Receive the welcome message
    recv_string_expect_success (sub, "W", 0);

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
