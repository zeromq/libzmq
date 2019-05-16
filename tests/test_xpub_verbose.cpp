/*
    Copyright (c) 2018 Contributors as noted in the AUTHORS file

    This file is part of libzmq, the ZeroMQ core engine in C++.

    libzmq is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License (LGPL) as published
    by the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    As a special exception, the Contributors give you permission to link
    this library with independent modules to produce an executable,
    regardless of the license terms of these independent modules, and to
    copy and distribute the resulting executable under terms of your choice,
    provided that you also meet, for each linked independent module, the
    terms and conditions of the license of that module. An independent
    module is a module which is not derived from or based on this library.
    If you modify this library, you must extend this exception to your
    version of the library.

    libzmq is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
    FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
    License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "testutil.hpp"
#include "testutil_unity.hpp"

SETUP_TEARDOWN_TESTCONTEXT

const uint8_t unsubscribe_a_msg[] = {0, 'A'};
const uint8_t subscribe_a_msg[] = {1, 'A'};
const uint8_t subscribe_b_msg[] = {1, 'B'};

const char test_endpoint[] = "inproc://soname";
const char topic_a[] = "A";
const char topic_b[] = "B";

void test_xpub_verbose_one_sub ()
{
    void *pub = test_context_socket (ZMQ_XPUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (pub, test_endpoint));

    void *sub = test_context_socket (ZMQ_SUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sub, test_endpoint));

    //  Subscribe for A
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (sub, ZMQ_SUBSCRIBE, topic_a, 1));

    // Receive subscriptions from subscriber
    recv_array_expect_success (pub, subscribe_a_msg, 0);

    // Subscribe socket for B instead
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (sub, ZMQ_SUBSCRIBE, topic_b, 1));

    // Receive subscriptions from subscriber
    recv_array_expect_success (pub, subscribe_b_msg, 0);

    //  Subscribe again for A again
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (sub, ZMQ_SUBSCRIBE, topic_a, 1));

    //  This time it is duplicated, so it will be filtered out
    TEST_ASSERT_FAILURE_ERRNO (EAGAIN, zmq_recv (pub, NULL, 0, ZMQ_DONTWAIT));

    int verbose = 1;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (pub, ZMQ_XPUB_VERBOSE, &verbose, sizeof (int)));

    // Subscribe socket for A again
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (sub, ZMQ_SUBSCRIBE, topic_a, 1));

    // This time with VERBOSE the duplicated sub will be received
    recv_array_expect_success (pub, subscribe_a_msg, 0);

    // Sending A message and B Message
    send_string_expect_success (pub, topic_a, 0);
    send_string_expect_success (pub, topic_b, 0);

    recv_string_expect_success (sub, topic_a, 0);
    recv_string_expect_success (sub, topic_b, 0);

    //  Clean up.
    test_context_socket_close (pub);
    test_context_socket_close (sub);
}

void create_xpub_with_2_subs (void **pub_, void **sub0_, void **sub1_)
{
    *pub_ = test_context_socket (ZMQ_XPUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (*pub_, test_endpoint));

    *sub0_ = test_context_socket (ZMQ_SUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (*sub0_, test_endpoint));

    *sub1_ = test_context_socket (ZMQ_SUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (*sub1_, test_endpoint));
}

void create_duplicate_subscription (void *pub_, void *sub0_, void *sub1_)
{
    //  Subscribe for A
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sub0_, ZMQ_SUBSCRIBE, topic_a, 1));

    // Receive subscriptions from subscriber
    recv_array_expect_success (pub_, subscribe_a_msg, 0);

    //  Subscribe again for A on the other socket
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sub1_, ZMQ_SUBSCRIBE, topic_a, 1));

    //  This time it is duplicated, so it will be filtered out by XPUB
    TEST_ASSERT_FAILURE_ERRNO (EAGAIN, zmq_recv (pub_, NULL, 0, ZMQ_DONTWAIT));
}

void test_xpub_verbose_two_subs ()
{
    void *pub, *sub0, *sub1;
    create_xpub_with_2_subs (&pub, &sub0, &sub1);
    create_duplicate_subscription (pub, sub0, sub1);

    // Subscribe socket for B instead
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sub0, ZMQ_SUBSCRIBE, topic_b, 1));

    // Receive subscriptions from subscriber
    recv_array_expect_success (pub, subscribe_b_msg, 0);

    int verbose = 1;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (pub, ZMQ_XPUB_VERBOSE, &verbose, sizeof (int)));

    // Subscribe socket for A again
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sub1, ZMQ_SUBSCRIBE, topic_a, 1));

    // This time with VERBOSE the duplicated sub will be received
    recv_array_expect_success (pub, subscribe_a_msg, 0);

    // Sending A message and B Message
    send_string_expect_success (pub, topic_a, 0);

    send_string_expect_success (pub, topic_b, 0);

    recv_string_expect_success (sub0, topic_a, 0);
    recv_string_expect_success (sub1, topic_a, 0);
    recv_string_expect_success (sub0, topic_b, 0);

    //  Clean up.
    test_context_socket_close (pub);
    test_context_socket_close (sub0);
    test_context_socket_close (sub1);
}

void test_xpub_verboser_one_sub ()
{
    //  Create a publisher
    void *pub = test_context_socket (ZMQ_XPUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (pub, test_endpoint));

    //  Create a subscriber
    void *sub = test_context_socket (ZMQ_SUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sub, test_endpoint));

    //  Unsubscribe for A, does not exist yet
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sub, ZMQ_UNSUBSCRIBE, topic_a, 1));

    //  Does not exist, so it will be filtered out by XSUB
    TEST_ASSERT_FAILURE_ERRNO (EAGAIN, zmq_recv (pub, NULL, 0, ZMQ_DONTWAIT));

    //  Subscribe for A
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (sub, ZMQ_SUBSCRIBE, topic_a, 1));

    // Receive subscriptions from subscriber
    recv_array_expect_success (pub, subscribe_a_msg, 0);

    //  Subscribe again for A again, XSUB will increase refcount
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (sub, ZMQ_SUBSCRIBE, topic_a, 1));

    //  This time it is duplicated, so it will be filtered out by XPUB
    TEST_ASSERT_FAILURE_ERRNO (EAGAIN, zmq_recv (pub, NULL, 0, ZMQ_DONTWAIT));

    //  Unsubscribe for A, this time it exists in XPUB
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sub, ZMQ_UNSUBSCRIBE, topic_a, 1));

    //  XSUB refcounts and will not actually send unsub to PUB until the number
    //  of unsubs match the earlier subs
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sub, ZMQ_UNSUBSCRIBE, topic_a, 1));

    // Receive unsubscriptions from subscriber
    recv_array_expect_success (pub, unsubscribe_a_msg, 0);

    //  XSUB only sends the last and final unsub, so XPUB will only receive 1
    TEST_ASSERT_FAILURE_ERRNO (EAGAIN, zmq_recv (pub, NULL, 0, ZMQ_DONTWAIT));

    //  Unsubscribe for A, does not exist anymore
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sub, ZMQ_UNSUBSCRIBE, topic_a, 1));

    //  Does not exist, so it will be filtered out by XSUB
    TEST_ASSERT_FAILURE_ERRNO (EAGAIN, zmq_recv (pub, NULL, 0, ZMQ_DONTWAIT));

    int verbose = 1;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (pub, ZMQ_XPUB_VERBOSER, &verbose, sizeof (int)));

    // Subscribe socket for A again
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (sub, ZMQ_SUBSCRIBE, topic_a, 1));

    // Receive subscriptions from subscriber, did not exist anymore
    recv_array_expect_success (pub, subscribe_a_msg, 0);

    // Sending A message to make sure everything still works
    send_string_expect_success (pub, topic_a, 0);

    recv_string_expect_success (sub, topic_a, 0);

    //  Unsubscribe for A, this time it exists
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sub, ZMQ_UNSUBSCRIBE, topic_a, 1));

    // Receive unsubscriptions from subscriber
    recv_array_expect_success (pub, unsubscribe_a_msg, 0);

    //  Unsubscribe for A again, it does not exist anymore so XSUB will filter
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sub, ZMQ_UNSUBSCRIBE, topic_a, 1));

    //  XSUB only sends unsub if it matched it in its trie, IOW: it will only
    //  send it if it existed in the first place even with XPUB_VERBBOSER
    TEST_ASSERT_FAILURE_ERRNO (EAGAIN, zmq_recv (pub, NULL, 0, ZMQ_DONTWAIT));

    //  Clean up.
    test_context_socket_close (pub);
    test_context_socket_close (sub);
}

void test_xpub_verboser_two_subs ()
{
    void *pub, *sub0, *sub1;
    create_xpub_with_2_subs (&pub, &sub0, &sub1);
    create_duplicate_subscription (pub, sub0, sub1);

    //  Unsubscribe for A, this time it exists in XPUB
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sub0, ZMQ_UNSUBSCRIBE, topic_a, 1));

    //  sub1 is still subscribed, so no notification
    TEST_ASSERT_FAILURE_ERRNO (EAGAIN, zmq_recv (pub, NULL, 0, ZMQ_DONTWAIT));

    //  Unsubscribe the second socket to trigger the notification
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sub1, ZMQ_UNSUBSCRIBE, topic_a, 1));

    // Receive unsubscriptions since all sockets are gone
    recv_array_expect_success (pub, unsubscribe_a_msg, 0);

    //  Make really sure there is only one notification
    TEST_ASSERT_FAILURE_ERRNO (EAGAIN, zmq_recv (pub, NULL, 0, ZMQ_DONTWAIT));

    int verbose = 1;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (pub, ZMQ_XPUB_VERBOSER, &verbose, sizeof (int)));

    // Subscribe socket for A again
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sub0, ZMQ_SUBSCRIBE, topic_a, 1));

    // Subscribe socket for A again
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sub1, ZMQ_SUBSCRIBE, topic_a, 1));

    // Receive subscriptions from subscriber, did not exist anymore
    recv_array_expect_success (pub, subscribe_a_msg, 0);

    //  VERBOSER is set, so subs from both sockets are received
    recv_array_expect_success (pub, subscribe_a_msg, 0);

    // Sending A message to make sure everything still works
    send_string_expect_success (pub, topic_a, 0);

    recv_string_expect_success (sub0, topic_a, 0);
    recv_string_expect_success (sub1, topic_a, 0);

    //  Unsubscribe for A
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sub1, ZMQ_UNSUBSCRIBE, topic_a, 1));

    // Receive unsubscriptions from first subscriber due to VERBOSER
    recv_array_expect_success (pub, unsubscribe_a_msg, 0);

    //  Unsubscribe for A again from the other socket
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sub0, ZMQ_UNSUBSCRIBE, topic_a, 1));

    // Receive unsubscriptions from first subscriber due to VERBOSER
    recv_array_expect_success (pub, unsubscribe_a_msg, 0);

    //  Unsubscribe again to make sure it gets filtered now
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sub1, ZMQ_UNSUBSCRIBE, topic_a, 1));

    //  Unmatched, so XSUB filters even with VERBOSER
    TEST_ASSERT_FAILURE_ERRNO (EAGAIN, zmq_recv (pub, NULL, 0, ZMQ_DONTWAIT));

    //  Clean up.
    test_context_socket_close (pub);
    test_context_socket_close (sub0);
    test_context_socket_close (sub1);
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_xpub_verbose_one_sub);
    RUN_TEST (test_xpub_verbose_two_subs);
    RUN_TEST (test_xpub_verboser_one_sub);
    RUN_TEST (test_xpub_verboser_two_subs);

    return UNITY_END ();
}
