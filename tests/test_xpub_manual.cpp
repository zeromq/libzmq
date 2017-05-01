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

int test_basic()
{
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    //  Create a publisher
    void *pub = zmq_socket (ctx, ZMQ_XPUB);
    assert (pub);
    int rc = zmq_bind (pub, "inproc://soname");
    assert (rc == 0);

    //  set pub socket options
    int manual = 1;
    rc = zmq_setsockopt(pub, ZMQ_XPUB_MANUAL, &manual, 4);
    assert (rc == 0);

    //  Create a subscriber
    void *sub = zmq_socket (ctx, ZMQ_XSUB);
    assert (sub);
    rc = zmq_connect (sub, "inproc://soname");
    assert (rc == 0);

    //  Subscribe for A
    char subscription[2] = { 1, 'A'};
    rc = zmq_send_const(sub, subscription, 2, 0);
    assert (rc == 2);

    char buffer[2];

    // Receive subscriptions from subscriber
    rc = zmq_recv(pub, buffer, 2, 0);
    assert(rc == 2);
    assert(buffer[0] == 1);
    assert(buffer[1] == 'A');

    // Subscribe socket for B instead
    rc = zmq_setsockopt(pub, ZMQ_SUBSCRIBE, "B", 1);
    assert(rc == 0);

    // Sending A message and B Message
    rc = zmq_send_const(pub, "A", 1, 0);
    assert(rc == 1);

    rc = zmq_send_const(pub, "B", 1, 0);
    assert(rc == 1);

    rc = zmq_recv(sub, buffer, 1, ZMQ_DONTWAIT);
    assert(rc == 1);
    assert(buffer[0] == 'B');

    //  Clean up.
    rc = zmq_close (pub);
    assert (rc == 0);
    rc = zmq_close (sub);
    assert (rc == 0);
    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    return 0 ;
}


int test_unsubscribe_manual()
{
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    //  Create a publisher
    void *pub = zmq_socket (ctx, ZMQ_XPUB);
    assert (pub);
    int rc = zmq_bind (pub, "inproc://soname");
    assert (rc == 0);

    //  set pub socket options
    int manual = 1;
    rc = zmq_setsockopt(pub, ZMQ_XPUB_MANUAL, &manual, 4);
    assert (rc == 0);

    //  Create a subscriber
    void *sub = zmq_socket (ctx, ZMQ_XSUB);
    assert (sub);
    rc = zmq_connect (sub, "inproc://soname");
    assert (rc == 0);

    //  Subscribe for A
    char subscription1[2] = { 1, 'A'};
    rc = zmq_send_const(sub, subscription1, 2, 0);
    assert (rc == 2);

    //  Subscribe for B
    char subscription2[2] = { 1, 'B'};
    rc = zmq_send_const(sub, subscription2, 2, 0);
    assert (rc == 2);

    char buffer[3];

    // Receive subscription "A" from subscriber
    rc = zmq_recv(pub, buffer, 2, 0);
    assert(rc == 2);
    assert(buffer[0] == 1);
    assert(buffer[1] == 'A');

    // Subscribe socket for XA instead
    rc = zmq_setsockopt(pub, ZMQ_SUBSCRIBE, "XA", 2);
    assert(rc == 0);

    // Receive subscription "B" from subscriber
    rc = zmq_recv(pub, buffer, 2, 0);
    assert(rc == 2);
    assert(buffer[0] == 1);
    assert(buffer[1] == 'B');

    // Subscribe socket for XB instead
    rc = zmq_setsockopt(pub, ZMQ_SUBSCRIBE, "XB", 2);
    assert(rc == 0);

    //  Unsubscribe from A
    char unsubscription1[2] = { 0, 'A'};
    rc = zmq_send_const(sub, unsubscription1, 2, 0);
    assert (rc == 2);

    // Receive unsubscription "A" from subscriber
    rc = zmq_recv(pub, buffer, 2, 0);
    assert(rc == 2);
    assert(buffer[0] == 0);
    assert(buffer[1] == 'A');

    // Unsubscribe socket from XA instead
    rc = zmq_setsockopt(pub, ZMQ_UNSUBSCRIBE, "XA", 2);
    assert(rc == 0);

    // Sending messages XA, XB
    rc = zmq_send_const(pub, "XA", 2, 0);
    assert(rc == 2);
    rc = zmq_send_const(pub, "XB", 2, 0);
    assert(rc == 2);

    // Subscriber should receive XB only
    rc = zmq_recv(sub, buffer, 2, ZMQ_DONTWAIT);
    assert(rc == 2);
    assert(buffer[0] == 'X');
    assert(buffer[1] == 'B');

    // Close subscriber
    rc = zmq_close (sub);
    assert (rc == 0);

    // Receive unsubscription "B"
    rc = zmq_recv(pub, buffer, 2, 0);
    assert(rc == 2);
    assert(buffer[0] == 0);
    assert(buffer[1] == 'B');

    // Unsubscribe socket from XB instead
    rc = zmq_setsockopt(pub, ZMQ_UNSUBSCRIBE, "XB", 2);
    assert(rc == 0);

    //  Clean up.
    rc = zmq_close (pub);
    assert (rc == 0);
    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    return 0 ;
}


int test_xpub_proxy_unsubscribe_on_disconnect(void)
{
    const char* topic = "1";
    const char* payload = "X";

    size_t len = MAX_SOCKET_STRING;
    char my_endpoint_backend[MAX_SOCKET_STRING];
    char my_endpoint_frontend[MAX_SOCKET_STRING];

    int manual = 1;

    void *ctx = zmq_ctx_new ();
    assert (ctx);

    // proxy frontend
    void *xsub_proxy = zmq_socket (ctx, ZMQ_XSUB);
    assert (xsub_proxy);
    assert (zmq_bind (xsub_proxy, "tcp://127.0.0.1:*") == 0);
    int rc = zmq_getsockopt (xsub_proxy, ZMQ_LAST_ENDPOINT, my_endpoint_frontend,
            &len);
    assert (rc == 0);

    // proxy backend
    void *xpub_proxy = zmq_socket (ctx, ZMQ_XPUB);
    assert (xpub_proxy);
    assert (zmq_setsockopt (xpub_proxy, ZMQ_XPUB_MANUAL, &manual, 4) == 0);
    assert (zmq_bind (xpub_proxy, "tcp://127.0.0.1:*") == 0);
    len = MAX_SOCKET_STRING;
    rc = zmq_getsockopt (xpub_proxy, ZMQ_LAST_ENDPOINT, my_endpoint_backend,
            &len);
    assert (rc == 0);

    // publisher
    void *pub = zmq_socket (ctx, ZMQ_PUB);
    assert (zmq_connect (pub, my_endpoint_frontend) == 0);

    // first subscriber subscribes
    void *sub1 = zmq_socket (ctx, ZMQ_SUB);
    assert (sub1);
    assert (zmq_connect (sub1, my_endpoint_backend) == 0);
    assert (zmq_setsockopt (sub1, ZMQ_SUBSCRIBE, topic, 1) == 0);

    // wait
    msleep (SETTLE_TIME);

    // proxy reroutes and confirms subscriptions
    char sub_buff[2];
    assert (zmq_recv (xpub_proxy, sub_buff, 2, ZMQ_DONTWAIT) == 2);
    assert (sub_buff [0] == 1);
    assert (sub_buff [1] == *topic);
    assert (zmq_setsockopt (xpub_proxy, ZMQ_SUBSCRIBE, topic, 1) == 0);
    assert (zmq_send (xsub_proxy, sub_buff, 2, 0) == 2);

    // second subscriber subscribes
    void *sub2 = zmq_socket (ctx, ZMQ_SUB);
    assert (sub2);
    assert (zmq_connect (sub2, my_endpoint_backend) == 0);
    assert (zmq_setsockopt (sub2, ZMQ_SUBSCRIBE, topic, 1) == 0);

    // wait
    msleep (SETTLE_TIME);

    // proxy reroutes
    assert (zmq_recv (xpub_proxy, sub_buff, 2, ZMQ_DONTWAIT) == 2);
    assert (sub_buff [0] == 1);
    assert (sub_buff [1] == *topic);
    assert (zmq_setsockopt (xpub_proxy, ZMQ_SUBSCRIBE, topic, 1) == 0);
    assert (zmq_send (xsub_proxy, sub_buff, 2, 0) == 2);

    // wait
    msleep (SETTLE_TIME);

    // let publisher send a msg
    assert (zmq_send (pub, topic, 1, ZMQ_SNDMORE) == 1);
    assert (zmq_send (pub, payload, 1, 0) == 1);

    // wait
    msleep (SETTLE_TIME);

    // proxy reroutes data messages to subscribers
    char topic_buff[1];
    char data_buff[1];
    assert (zmq_recv (xsub_proxy, topic_buff, 1, ZMQ_DONTWAIT) == 1);
    assert (topic_buff [0] == *topic);
    assert (zmq_recv (xsub_proxy, data_buff, 1, ZMQ_DONTWAIT) == 1);
    assert (data_buff [0] == *payload);
    assert (zmq_send (xpub_proxy, topic_buff, 1, ZMQ_SNDMORE) == 1);
    assert (zmq_send (xpub_proxy, data_buff, 1, 0) == 1);

    // wait
    msleep (SETTLE_TIME);

    // each subscriber should now get a message
    assert (zmq_recv (sub2, topic_buff, 1, ZMQ_DONTWAIT) == 1);
    assert (topic_buff [0] == *topic);
    assert (zmq_recv (sub2, data_buff, 1, ZMQ_DONTWAIT) == 1);
    assert (data_buff [0] == *payload);

    assert (zmq_recv (sub1, topic_buff, 1, ZMQ_DONTWAIT) == 1);
    assert (topic_buff [0] == *topic);
    assert (zmq_recv (sub1, data_buff, 1, ZMQ_DONTWAIT) == 1);
    assert (data_buff [0] == *payload);

    //  Disconnect both subscribers
    assert (zmq_close (sub1) == 0);
    assert (zmq_close (sub2) == 0);

    // wait
    msleep (SETTLE_TIME);

    // unsubscribe messages are passed from proxy to publisher
    assert (zmq_recv (xpub_proxy, sub_buff, 2, 0) == 2);
    assert (sub_buff [0] == 0);
    assert (sub_buff [1] == *topic);
    assert (zmq_setsockopt (xpub_proxy, ZMQ_UNSUBSCRIBE, topic, 1) == 0);
    assert (zmq_send (xsub_proxy, sub_buff, 2, 0) == 2);

    // should receive another unsubscribe msg
    assert (zmq_recv (xpub_proxy, sub_buff, 2, 0) == 2
        && "Should receive the second unsubscribe message.");
    assert (sub_buff [0] == 0);
    assert (sub_buff [1] == *topic);
    assert (zmq_setsockopt (xpub_proxy, ZMQ_UNSUBSCRIBE, topic, 1) == 0);
    assert (zmq_send (xsub_proxy, sub_buff, 2, 0) == 2);

    // wait
    msleep (SETTLE_TIME);

    // let publisher send a msg
    assert (zmq_send (pub, topic, 1, ZMQ_SNDMORE) == 1);
    assert (zmq_send (pub, payload, 1, 0) == 1);

     // wait
    msleep (SETTLE_TIME);

    // nothing should come to the proxy
    assert (zmq_recv (xsub_proxy, topic_buff, 1, ZMQ_DONTWAIT) == -1);
    assert (errno == EAGAIN);

    assert (zmq_close (pub) == 0);
    assert (zmq_close (xpub_proxy) == 0);
    assert (zmq_close (xsub_proxy) == 0);
    assert (zmq_ctx_term (ctx) == 0);

    return 0;
}

int test_missing_subscriptions(void)
{
    const char* topic1 = "1";
    const char* topic2 = "2";
    const char* payload = "X";

    size_t len = MAX_SOCKET_STRING;
    char my_endpoint_backend[MAX_SOCKET_STRING];
    char my_endpoint_frontend[MAX_SOCKET_STRING];

    int manual = 1;

    void *ctx = zmq_ctx_new ();
    assert (ctx);

    // proxy frontend
    void *xsub_proxy = zmq_socket (ctx, ZMQ_XSUB);
    assert (xsub_proxy);
    assert (zmq_bind (xsub_proxy, "tcp://127.0.0.1:*") == 0);
    int rc = zmq_getsockopt (xsub_proxy, ZMQ_LAST_ENDPOINT, my_endpoint_frontend,
            &len);
    assert (rc == 0);

    // proxy backend
    void *xpub_proxy = zmq_socket (ctx, ZMQ_XPUB);
    assert (xpub_proxy);
    assert (zmq_setsockopt (xpub_proxy, ZMQ_XPUB_MANUAL, &manual, 4) == 0);
    assert (zmq_bind (xpub_proxy, "tcp://127.0.0.1:*") == 0);
    len = MAX_SOCKET_STRING;
    rc = zmq_getsockopt (xpub_proxy, ZMQ_LAST_ENDPOINT, my_endpoint_backend,
            &len);
    assert (rc == 0);

    // publisher
    void *pub = zmq_socket (ctx, ZMQ_PUB);
    assert (zmq_connect (pub, my_endpoint_frontend) == 0);

    // Here's the problem: because subscribers subscribe in quick succession,
    // the proxy is unable to confirm the first subscription before receiving
    // the second. This causes the first subscription to get lost.

    // first subscriber
    void *sub1 = zmq_socket (ctx, ZMQ_SUB);
    assert (sub1);
    assert (zmq_connect (sub1, my_endpoint_backend) == 0);
    assert (zmq_setsockopt (sub1, ZMQ_SUBSCRIBE, topic1, 1) == 0);

    // second subscriber
    void *sub2 = zmq_socket (ctx, ZMQ_SUB);
    assert (sub2);
    assert (zmq_connect (sub2, my_endpoint_backend) == 0);
    assert (zmq_setsockopt (sub2, ZMQ_SUBSCRIBE, topic2, 1) == 0);

    // wait
    msleep (SETTLE_TIME);

    // proxy now reroutes and confirms subscriptions
    char buffer[2];
    assert (zmq_recv (xpub_proxy, buffer, 2, ZMQ_DONTWAIT) == 2);
    assert (buffer [0] == 1);
    assert (buffer [1] == *topic1);
    assert (zmq_setsockopt (xpub_proxy, ZMQ_SUBSCRIBE, topic1, 1) == 0);
    assert (zmq_send (xsub_proxy, buffer, 2, 0) == 2);

    assert (zmq_recv (xpub_proxy, buffer, 2, ZMQ_DONTWAIT) == 2);
    assert (buffer [0] == 1);
    assert (buffer [1] == *topic2);
    assert (zmq_setsockopt (xpub_proxy, ZMQ_SUBSCRIBE, topic2, 1) == 0);
    assert (zmq_send (xsub_proxy, buffer, 2, 0) == 2);

    // wait
    msleep (SETTLE_TIME);

    // let publisher send 2 msgs, each with its own topic
    assert (zmq_send (pub, topic1, 1, ZMQ_SNDMORE) == 1);
    assert (zmq_send (pub, payload, 1, 0) == 1);
    assert (zmq_send (pub, topic2, 1, ZMQ_SNDMORE) == 1);
    assert (zmq_send (pub, payload, 1, 0) == 1);

    // wait
    msleep (SETTLE_TIME);

    // proxy reroutes data messages to subscribers
    char topic_buff [1];
    char data_buff [1];
    assert (zmq_recv (xsub_proxy, topic_buff, 1, ZMQ_DONTWAIT) == 1);
    assert (topic_buff [0] == *topic1);
    assert (zmq_recv (xsub_proxy, data_buff, 1, ZMQ_DONTWAIT) == 1);
    assert (data_buff [0] == *payload);
    assert (zmq_send (xpub_proxy, topic_buff, 1, ZMQ_SNDMORE) == 1);
    assert (zmq_send (xpub_proxy, data_buff, 1, 0) == 1);

    assert (zmq_recv (xsub_proxy, topic_buff, 1, ZMQ_DONTWAIT) == 1);
    assert (topic_buff [0] == *topic2);
    assert (zmq_recv (xsub_proxy, data_buff, 1, ZMQ_DONTWAIT) == 1);
    assert (data_buff [0] == *payload);
    assert (zmq_send (xpub_proxy, topic_buff, 1, ZMQ_SNDMORE) == 1);
    assert (zmq_send (xpub_proxy, data_buff, 1, 0) == 1);

    // wait
    msleep (SETTLE_TIME);

    // each subscriber should now get a message
    assert (zmq_recv (sub2, topic_buff, 1, ZMQ_DONTWAIT) == 1);
    assert (topic_buff [0] == *topic2);
    assert (zmq_recv (sub2, data_buff, 1, ZMQ_DONTWAIT) == 1);
    assert (data_buff [0] == *payload);

    assert (zmq_recv (sub1, topic_buff, 1, ZMQ_DONTWAIT) == 1);
    assert (topic_buff [0] == *topic1);
    assert (zmq_recv (sub1, data_buff, 1, ZMQ_DONTWAIT) == 1);
    assert (data_buff [0] == *payload);

    //  Clean up
    assert (zmq_close (sub1) == 0);
    assert (zmq_close (sub2) == 0);
    assert (zmq_close (pub) == 0);
    assert (zmq_close (xpub_proxy) == 0);
    assert (zmq_close (xsub_proxy) == 0);
    assert (zmq_ctx_term (ctx) == 0);

    return 0;
}


int main(void)
{
    setup_test_environment ();
    test_basic ();
    test_unsubscribe_manual ();
    test_xpub_proxy_unsubscribe_on_disconnect ();
    test_missing_subscriptions ();

    return 0;
}
