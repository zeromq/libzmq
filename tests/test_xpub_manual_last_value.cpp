/*
    Copyright (c) 2007-2017 Contributors as noted in the AUTHORS file

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

void test_basic ()
{
    //  Create a publisher
    void *pub = test_context_socket (ZMQ_XPUB);
    int manual = 1;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (pub, ZMQ_XPUB_MANUAL_LAST_VALUE, &manual, 4));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (pub, "inproc://soname"));

    //  Create a subscriber
    void *sub = test_context_socket (ZMQ_XSUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sub, "inproc://soname"));

    //  Subscribe for A
    const char subscription[] = {1, 'A', 0};
    send_string_expect_success (sub, subscription, 0);

    // Receive subscriptions from subscriber
    recv_string_expect_success (pub, subscription, 0);

    // Subscribe socket for B instead
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (pub, ZMQ_SUBSCRIBE, "B", 1));

    // Sending A message and B Message
    send_string_expect_success (pub, "A", 0);
    send_string_expect_success (pub, "B", 0);

    recv_string_expect_success (sub, "B", ZMQ_DONTWAIT);

    //  Clean up.
    test_context_socket_close (pub);
    test_context_socket_close (sub);
}

void test_unsubscribe_manual ()
{
    //  Create a publisher
    void *pub = test_context_socket (ZMQ_XPUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (pub, "inproc://soname"));

    //  set pub socket options
    int manual = 1;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (pub, ZMQ_XPUB_MANUAL_LAST_VALUE,
                                               &manual, sizeof (manual)));

    //  Create a subscriber
    void *sub = test_context_socket (ZMQ_XSUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sub, "inproc://soname"));

    //  Subscribe for A
    const uint8_t subscription1[] = {1, 'A'};
    send_array_expect_success (sub, subscription1, 0);

    //  Subscribe for B
    const uint8_t subscription2[] = {1, 'B'};
    send_array_expect_success (sub, subscription2, 0);

    char buffer[3];

    // Receive subscription "A" from subscriber
    recv_array_expect_success (pub, subscription1, 0);

    // Subscribe socket for XA instead
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (pub, ZMQ_SUBSCRIBE, "XA", 2));

    // Receive subscription "B" from subscriber
    recv_array_expect_success (pub, subscription2, 0);

    // Subscribe socket for XB instead
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (pub, ZMQ_SUBSCRIBE, "XB", 2));

    //  Unsubscribe from A
    const uint8_t unsubscription1[2] = {0, 'A'};
    send_array_expect_success (sub, unsubscription1, 0);

    // Receive unsubscription "A" from subscriber
    recv_array_expect_success (pub, unsubscription1, 0);

    // Unsubscribe socket from XA instead
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (pub, ZMQ_UNSUBSCRIBE, "XA", 2));

    // Sending messages XA, XB
    send_string_expect_success (pub, "XA", 0);
    send_string_expect_success (pub, "XB", 0);

    // Subscriber should receive XB only
    recv_string_expect_success (sub, "XB", ZMQ_DONTWAIT);

    // Close subscriber
    test_context_socket_close (sub);

    // Receive unsubscription "B"
    const char unsubscription2[2] = {0, 'B'};
    TEST_ASSERT_EQUAL_INT (
      sizeof unsubscription2,
      TEST_ASSERT_SUCCESS_ERRNO (zmq_recv (pub, buffer, sizeof buffer, 0)));
    TEST_ASSERT_EQUAL_INT8_ARRAY (unsubscription2, buffer,
                                  sizeof unsubscription2);

    // Unsubscribe socket from XB instead
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (pub, ZMQ_UNSUBSCRIBE, "XB", 2));

    //  Clean up.
    test_context_socket_close (pub);
}

void test_xpub_proxy_unsubscribe_on_disconnect ()
{
    const uint8_t topic_buff[] = {"1"};
    const uint8_t payload_buff[] = {"X"};

    char my_endpoint_backend[MAX_SOCKET_STRING];
    char my_endpoint_frontend[MAX_SOCKET_STRING];

    int manual = 1;

    // proxy frontend
    void *xsub_proxy = test_context_socket (ZMQ_XSUB);
    bind_loopback_ipv4 (xsub_proxy, my_endpoint_frontend,
                        sizeof my_endpoint_frontend);

    // proxy backend
    void *xpub_proxy = test_context_socket (ZMQ_XPUB);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (xpub_proxy, ZMQ_XPUB_MANUAL_LAST_VALUE, &manual, 4));
    bind_loopback_ipv4 (xpub_proxy, my_endpoint_backend,
                        sizeof my_endpoint_backend);

    // publisher
    void *pub = test_context_socket (ZMQ_PUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (pub, my_endpoint_frontend));

    // first subscriber subscribes
    void *sub1 = test_context_socket (ZMQ_SUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sub1, my_endpoint_backend));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sub1, ZMQ_SUBSCRIBE, topic_buff, 1));

    // wait
    msleep (SETTLE_TIME);

    // proxy reroutes and confirms subscriptions
    const uint8_t subscription[2] = {1, *topic_buff};
    recv_array_expect_success (xpub_proxy, subscription, ZMQ_DONTWAIT);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (xpub_proxy, ZMQ_SUBSCRIBE, topic_buff, 1));
    send_array_expect_success (xsub_proxy, subscription, 0);

    // second subscriber subscribes
    void *sub2 = test_context_socket (ZMQ_SUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sub2, my_endpoint_backend));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sub2, ZMQ_SUBSCRIBE, topic_buff, 1));

    // wait
    msleep (SETTLE_TIME);

    // proxy reroutes
    recv_array_expect_success (xpub_proxy, subscription, ZMQ_DONTWAIT);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (xpub_proxy, ZMQ_SUBSCRIBE, topic_buff, 1));
    send_array_expect_success (xsub_proxy, subscription, 0);

    // wait
    msleep (SETTLE_TIME);

    // let publisher send a msg
    send_array_expect_success (pub, topic_buff, ZMQ_SNDMORE);
    send_array_expect_success (pub, payload_buff, 0);

    // wait
    msleep (SETTLE_TIME);

    // proxy reroutes data messages to subscribers
    recv_array_expect_success (xsub_proxy, topic_buff, ZMQ_DONTWAIT);
    recv_array_expect_success (xsub_proxy, payload_buff, ZMQ_DONTWAIT);

    // send 2 messages
    send_array_expect_success (xpub_proxy, topic_buff, ZMQ_SNDMORE);
    send_array_expect_success (xpub_proxy, payload_buff, 0);
    send_array_expect_success (xpub_proxy, topic_buff, ZMQ_SNDMORE);
    send_array_expect_success (xpub_proxy, payload_buff, 0);

    // wait
    msleep (SETTLE_TIME);

    // sub2 will get 2 messages because the last subscription is sub2.
    recv_array_expect_success (sub2, topic_buff, ZMQ_DONTWAIT);
    recv_array_expect_success (sub2, payload_buff, ZMQ_DONTWAIT);
    recv_array_expect_success (sub2, topic_buff, ZMQ_DONTWAIT);
    recv_array_expect_success (sub2, payload_buff, ZMQ_DONTWAIT);

    recv_array_expect_success (sub1, topic_buff, ZMQ_DONTWAIT);
    recv_array_expect_success (sub1, payload_buff, ZMQ_DONTWAIT);

    //  Disconnect both subscribers
    test_context_socket_close (sub1);
    test_context_socket_close (sub2);

    // wait
    msleep (SETTLE_TIME);

    // unsubscribe messages are passed from proxy to publisher
    const uint8_t unsubscription[] = {0, *topic_buff};
    recv_array_expect_success (xpub_proxy, unsubscription, 0);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (xpub_proxy, ZMQ_UNSUBSCRIBE, topic_buff, 1));
    send_array_expect_success (xsub_proxy, unsubscription, 0);

    // should receive another unsubscribe msg
    recv_array_expect_success (xpub_proxy, unsubscription, 0);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (xpub_proxy, ZMQ_UNSUBSCRIBE, topic_buff, 1));
    send_array_expect_success (xsub_proxy, unsubscription, 0);

    // wait
    msleep (SETTLE_TIME);

    // let publisher send a msg
    send_array_expect_success (pub, topic_buff, ZMQ_SNDMORE);
    send_array_expect_success (pub, payload_buff, 0);

    // wait
    msleep (SETTLE_TIME);

    // nothing should come to the proxy
    char buffer[1];
    TEST_ASSERT_FAILURE_ERRNO (
      EAGAIN, zmq_recv (xsub_proxy, buffer, sizeof buffer, ZMQ_DONTWAIT));

    test_context_socket_close (pub);
    test_context_socket_close (xpub_proxy);
    test_context_socket_close (xsub_proxy);
}

void test_missing_subscriptions ()
{
    const char *topic1 = "1";
    const char *topic2 = "2";
    const char *payload = "X";

    char my_endpoint_backend[MAX_SOCKET_STRING];
    char my_endpoint_frontend[MAX_SOCKET_STRING];

    int manual = 1;

    // proxy frontend
    void *xsub_proxy = test_context_socket (ZMQ_XSUB);
    bind_loopback_ipv4 (xsub_proxy, my_endpoint_frontend,
                        sizeof my_endpoint_frontend);

    // proxy backend
    void *xpub_proxy = test_context_socket (ZMQ_XPUB);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (xpub_proxy, ZMQ_XPUB_MANUAL_LAST_VALUE, &manual, 4));
    bind_loopback_ipv4 (xpub_proxy, my_endpoint_backend,
                        sizeof my_endpoint_backend);

    // publisher
    void *pub = test_context_socket (ZMQ_PUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (pub, my_endpoint_frontend));

    // Here's the problem: because subscribers subscribe in quick succession,
    // the proxy is unable to confirm the first subscription before receiving
    // the second. This causes the first subscription to get lost.

    // first subscriber
    void *sub1 = test_context_socket (ZMQ_SUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sub1, my_endpoint_backend));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (sub1, ZMQ_SUBSCRIBE, topic1, 1));

    // wait
    msleep (SETTLE_TIME);

    // proxy now reroutes and confirms subscriptions
    const uint8_t subscription1[] = {1, static_cast<uint8_t> (topic1[0])};
    recv_array_expect_success (xpub_proxy, subscription1, ZMQ_DONTWAIT);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (xpub_proxy, ZMQ_SUBSCRIBE, topic1, 1));
    send_array_expect_success (xsub_proxy, subscription1, 0);

    // second subscriber
    void *sub2 = test_context_socket (ZMQ_SUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sub2, my_endpoint_backend));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (sub2, ZMQ_SUBSCRIBE, topic2, 1));

    // wait
    msleep (SETTLE_TIME);

    // proxy now reroutes and confirms subscriptions
    const uint8_t subscription2[] = {1, static_cast<uint8_t> (topic2[0])};
    recv_array_expect_success (xpub_proxy, subscription2, ZMQ_DONTWAIT);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (xpub_proxy, ZMQ_SUBSCRIBE, topic2, 1));
    send_array_expect_success (xsub_proxy, subscription2, 0);

    // wait
    msleep (SETTLE_TIME);

    // let publisher send 2 msgs, each with its own topic_buff
    send_string_expect_success (pub, topic1, ZMQ_SNDMORE);
    send_string_expect_success (pub, payload, 0);
    send_string_expect_success (pub, topic2, ZMQ_SNDMORE);
    send_string_expect_success (pub, payload, 0);

    // wait
    msleep (SETTLE_TIME);

    // proxy reroutes data messages to subscribers
    recv_string_expect_success (xsub_proxy, topic1, ZMQ_DONTWAIT);
    recv_string_expect_success (xsub_proxy, payload, ZMQ_DONTWAIT);
    send_string_expect_success (xpub_proxy, topic1, ZMQ_SNDMORE);
    send_string_expect_success (xpub_proxy, payload, 0);

    recv_string_expect_success (xsub_proxy, topic2, ZMQ_DONTWAIT);
    recv_string_expect_success (xsub_proxy, payload, ZMQ_DONTWAIT);
    send_string_expect_success (xpub_proxy, topic2, ZMQ_SNDMORE);
    send_string_expect_success (xpub_proxy, payload, 0);

    // wait
    msleep (SETTLE_TIME);

    // only sub2 should now get a message
    recv_string_expect_success (sub2, topic2, ZMQ_DONTWAIT);
    recv_string_expect_success (sub2, payload, ZMQ_DONTWAIT);

    //recv_string_expect_success (sub1, topic1, ZMQ_DONTWAIT);
    //recv_string_expect_success (sub1, payload, ZMQ_DONTWAIT);

    //  Clean up
    test_context_socket_close (sub1);
    test_context_socket_close (sub2);
    test_context_socket_close (pub);
    test_context_socket_close (xpub_proxy);
    test_context_socket_close (xsub_proxy);
}

void test_unsubscribe_cleanup ()
{
    char my_endpoint[MAX_SOCKET_STRING];

    //  Create a publisher
    void *pub = test_context_socket (ZMQ_XPUB);
    int manual = 1;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (pub, ZMQ_XPUB_MANUAL_LAST_VALUE, &manual, 4));
    bind_loopback_ipv4 (pub, my_endpoint, sizeof my_endpoint);

    //  Create a subscriber
    void *sub = test_context_socket (ZMQ_XSUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sub, my_endpoint));

    //  Subscribe for A
    const uint8_t subscription1[2] = {1, 'A'};
    send_array_expect_success (sub, subscription1, 0);


    // Receive subscriptions from subscriber
    recv_array_expect_success (pub, subscription1, 0);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (pub, ZMQ_SUBSCRIBE, "XA", 2));

    // send 2 messages
    send_string_expect_success (pub, "XA", 0);
    send_string_expect_success (pub, "XB", 0);

    // receive the single message
    recv_string_expect_success (sub, "XA", 0);

    // should be nothing left in the queue
    char buffer[2];
    TEST_ASSERT_FAILURE_ERRNO (
      EAGAIN, zmq_recv (sub, buffer, sizeof buffer, ZMQ_DONTWAIT));

    // close the socket
    test_context_socket_close (sub);

    // closing the socket will result in an unsubscribe event
    const uint8_t unsubscription[2] = {0, 'A'};
    recv_array_expect_success (pub, unsubscription, 0);

    // this doesn't really do anything
    // there is no last_pipe set it will just fail silently
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (pub, ZMQ_UNSUBSCRIBE, "XA", 2));

    // reconnect
    sub = test_context_socket (ZMQ_XSUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sub, my_endpoint));

    // send a subscription for B
    const uint8_t subscription2[2] = {1, 'B'};
    send_array_expect_success (sub, subscription2, 0);

    // receive the subscription, overwrite it to XB
    recv_array_expect_success (pub, subscription2, 0);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (pub, ZMQ_SUBSCRIBE, "XB", 2));

    // send 2 messages
    send_string_expect_success (pub, "XA", 0);
    send_string_expect_success (pub, "XB", 0);

    // receive the single message
    recv_string_expect_success (sub, "XB", 0);

    // should be nothing left in the queue
    TEST_ASSERT_FAILURE_ERRNO (
      EAGAIN, zmq_recv (sub, buffer, sizeof buffer, ZMQ_DONTWAIT));

    //  Clean up.
    test_context_socket_close (pub);
    test_context_socket_close (sub);
}

void test_manual_last_value ()
{
    //  Create a publisher
    void *pub = test_context_socket (ZMQ_XPUB);

    int hwm = 2000;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (pub, ZMQ_SNDHWM, &hwm, 4));

    //  set pub socket options
    int manual = 1;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (pub, ZMQ_XPUB_MANUAL_LAST_VALUE, &manual, 4));

    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (pub, "inproc://soname"));

    //  Create a subscriber
    void *sub = test_context_socket (ZMQ_SUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sub, "inproc://soname"));

    //  Create another subscriber
    void *sub2 = test_context_socket (ZMQ_SUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sub2, "inproc://soname"));

    //  Subscribe for "A".
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (sub, ZMQ_SUBSCRIBE, "A", 1));

    const uint8_t subscription[2] = {1, 'A'};
    //  we must wait for the subscription to be processed here, otherwise some
    //  or all published messages might be lost
    recv_array_expect_success (pub, subscription, 0);

    //  manual subscribe message
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (pub, ZMQ_SUBSCRIBE, "A", 1));
    send_string_expect_success (pub, "A", 0);
    recv_string_expect_success (sub, "A", 0);

    //  Subscribe for "A".
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (sub2, ZMQ_SUBSCRIBE, "A", 1));
    recv_array_expect_success (pub, subscription, 0);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (pub, ZMQ_SUBSCRIBE, "A", 1));
    send_string_expect_success (pub, "A", 0);
    recv_string_expect_success (sub2, "A", 0);

    char buffer[255];
    //  sub won't get a message because the last subscription pipe is sub2.
    TEST_ASSERT_FAILURE_ERRNO (
      EAGAIN, zmq_recv (sub, buffer, sizeof (buffer), ZMQ_DONTWAIT));

    //  Clean up.
    test_context_socket_close (pub);
    test_context_socket_close (sub);
    test_context_socket_close (sub2);
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_basic);
    RUN_TEST (test_unsubscribe_manual);
    RUN_TEST (test_xpub_proxy_unsubscribe_on_disconnect);
    RUN_TEST (test_missing_subscriptions);
    RUN_TEST (test_unsubscribe_cleanup);
    RUN_TEST (test_manual_last_value);

    return UNITY_END ();
}
