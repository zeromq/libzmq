/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

SETUP_TEARDOWN_TESTCONTEXT

const uint8_t unsubscribe_a_msg[] = {0, 'A'};
const uint8_t subscribe_a_msg[] = {1, 'A'};

const char test_endpoint[] = "inproc://soname";

void test_xsub_verbose_unsubscribe ()
{
    void *pub = test_context_socket (ZMQ_XPUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (pub, test_endpoint));

    void *sub = test_context_socket (ZMQ_XSUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sub, test_endpoint));

    // set option ZMQ_XPUB_VERBOSER to get all messages
    int xbup_verboser = 1;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (pub, ZMQ_XPUB_VERBOSER, &xbup_verboser, sizeof (int)));

    // unsubscribe from topic A, does not exist yet
    send_array_expect_success (sub, unsubscribe_a_msg, 0);

    // does not exist, so it will be filtered out by XSUB
    TEST_ASSERT_FAILURE_ERRNO (EAGAIN, zmq_recv (pub, NULL, 0, ZMQ_DONTWAIT));

    // subscribe to topic A
    send_array_expect_success (sub, subscribe_a_msg, 0);

    // receive subscription from subscriber
    recv_array_expect_success (pub, subscribe_a_msg, 0);

    // subscribe again to topic A
    send_array_expect_success (sub, subscribe_a_msg, 0);

    // receive subscription from subscriber
    recv_array_expect_success (pub, subscribe_a_msg, 0);

    // unsubscribe from topic A
    send_array_expect_success (sub, unsubscribe_a_msg, 0);

    // The first unsubscribe will be filtered out
    TEST_ASSERT_FAILURE_ERRNO (EAGAIN, zmq_recv (pub, NULL, 0, ZMQ_DONTWAIT));

    // unsubscribe again from topic A
    send_array_expect_success (sub, unsubscribe_a_msg, 0);

    // receive unsubscription from subscriber
    recv_array_expect_success (pub, unsubscribe_a_msg, 0);

    // set option ZMQ_XSUB_VERBOSE_UNSUBSCRIBE to get duplicate unsubscribes
    int xsub_verbose = 1;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      sub, ZMQ_XSUB_VERBOSE_UNSUBSCRIBE, &xsub_verbose, sizeof (int)));

    // unsubscribe from topic A, does not exist yet
    send_array_expect_success (sub, unsubscribe_a_msg, 0);

    // does not exist, but with ZMQ_XSUB_VERBOSE_UNSUBSCRIBE set it will be forwarded anyway
    recv_array_expect_success (pub, unsubscribe_a_msg, 0);

    // subscribe to topic A
    send_array_expect_success (sub, subscribe_a_msg, 0);

    // receive subscription from subscriber
    recv_array_expect_success (pub, subscribe_a_msg, 0);

    // subscribe again to topic A
    send_array_expect_success (sub, subscribe_a_msg, 0);

    // receive subscription from subscriber
    recv_array_expect_success (pub, subscribe_a_msg, 0);

    // unsubscribe from topic A
    send_array_expect_success (sub, unsubscribe_a_msg, 0);

    // receive unsubscription from subscriber
    recv_array_expect_success (pub, unsubscribe_a_msg, 0);

    // unsubscribe again from topic A
    send_array_expect_success (sub, unsubscribe_a_msg, 0);

    // receive unsubscription from subscriber
    recv_array_expect_success (pub, unsubscribe_a_msg, 0);

    //  Clean up.
    test_context_socket_close (pub);
    test_context_socket_close (sub);
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_xsub_verbose_unsubscribe);

    return UNITY_END ();
}
