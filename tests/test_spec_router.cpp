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

#include <stdlib.h>
#include <string.h>

SETUP_TEARDOWN_TESTCONTEXT

// SHALL receive incoming messages from its peers using a fair-queuing
// strategy.
void test_fair_queue_in (const char *bind_address)
{
    char connect_address[MAX_SOCKET_STRING];
    void *receiver = test_context_socket (ZMQ_ROUTER);

    int timeout = 250;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (receiver, ZMQ_RCVTIMEO, &timeout, sizeof (int)));

    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (receiver, bind_address));
    size_t len = MAX_SOCKET_STRING;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (receiver, ZMQ_LAST_ENDPOINT, connect_address, &len));

    const unsigned char services = 5;
    void *senders[services];
    for (unsigned char peer = 0; peer < services; ++peer) {
        senders[peer] = test_context_socket (ZMQ_DEALER);

        TEST_ASSERT_SUCCESS_ERRNO (
          zmq_setsockopt (senders[peer], ZMQ_RCVTIMEO, &timeout, sizeof (int)));

        char *str = strdup ("A");
        str[0] += peer;
        TEST_ASSERT_SUCCESS_ERRNO (
          zmq_setsockopt (senders[peer], ZMQ_ROUTING_ID, str, 2));
        free (str);

        TEST_ASSERT_SUCCESS_ERRNO (
          zmq_connect (senders[peer], connect_address));
    }

    msleep (SETTLE_TIME);

    zmq_msg_t msg;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init (&msg));

    s_send_seq (senders[0], "M", SEQ_END);
    s_recv_seq (receiver, "A", "M", SEQ_END);

    s_send_seq (senders[0], "M", SEQ_END);
    s_recv_seq (receiver, "A", "M", SEQ_END);

    int sum = 0;

    // send N requests
    for (unsigned char peer = 0; peer < services; ++peer) {
        s_send_seq (senders[peer], "M", SEQ_END);
        sum += 'A' + peer;
    }

    TEST_ASSERT_EQUAL_INT (services * 'A' + services * (services - 1) / 2, sum);

    // handle N requests
    for (unsigned char peer = 0; peer < services; ++peer) {
        TEST_ASSERT_EQUAL_INT (
          2, TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_recv (&msg, receiver, 0)));
        const char *id = static_cast<const char *> (zmq_msg_data (&msg));
        sum -= id[0];

        s_recv_seq (receiver, "M", SEQ_END);
    }

    TEST_ASSERT_EQUAL_INT (0, sum);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg));

    test_context_socket_close_zero_linger (receiver);

    for (size_t peer = 0; peer < services; ++peer)
        test_context_socket_close_zero_linger (senders[peer]);

    // Wait for disconnects.
    msleep (SETTLE_TIME);
}

// SHALL create a double queue when a peer connects to it. If this peer
// disconnects, the ROUTER socket SHALL destroy its double queue and SHALL
// discard any messages it contains.
void test_destroy_queue_on_disconnect (const char *bind_address)
{
    void *a = test_context_socket (ZMQ_ROUTER);

    int enabled = 1;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (a, ZMQ_ROUTER_MANDATORY, &enabled, sizeof (enabled)));

    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (a, bind_address));
    size_t len = MAX_SOCKET_STRING;
    char connect_address[MAX_SOCKET_STRING];
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (a, ZMQ_LAST_ENDPOINT, connect_address, &len));

    void *b = test_context_socket (ZMQ_DEALER);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (b, ZMQ_ROUTING_ID, "B", 2));

    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (b, connect_address));

    // Wait for connection.
    msleep (SETTLE_TIME);

    // Send a message in both directions
    s_send_seq (a, "B", "ABC", SEQ_END);
    s_send_seq (b, "DEF", SEQ_END);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_disconnect (b, connect_address));

    // Disconnect may take time and need command processing.
    zmq_pollitem_t poller[2] = {{a, 0, 0, 0}, {b, 0, 0, 0}};
    TEST_ASSERT_SUCCESS_ERRNO (zmq_poll (poller, 2, 100));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_poll (poller, 2, 100));

    // No messages should be available, sending should fail.
    zmq_msg_t msg;
    zmq_msg_init (&msg);

    TEST_ASSERT_FAILURE_ERRNO (
      EHOSTUNREACH, zmq_send (a, "B", 2, ZMQ_SNDMORE | ZMQ_DONTWAIT));

    TEST_ASSERT_FAILURE_ERRNO (EAGAIN, zmq_msg_recv (&msg, a, ZMQ_DONTWAIT));

    // After a reconnect of B, the messages should still be gone
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (b, connect_address));

    TEST_ASSERT_FAILURE_ERRNO (EAGAIN, zmq_msg_recv (&msg, a, ZMQ_DONTWAIT));

    TEST_ASSERT_FAILURE_ERRNO (EAGAIN, zmq_msg_recv (&msg, b, ZMQ_DONTWAIT));

    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg));

    test_context_socket_close_zero_linger (a);
    test_context_socket_close_zero_linger (b);

    // Wait for disconnects.
    msleep (SETTLE_TIME);
}

#define TEST_SUITE(name, bind_address)                                         \
    void test_fair_queue_in_##name () { test_fair_queue_in (bind_address); }   \
    void test_destroy_queue_on_disconnect_##name ()                            \
    {                                                                          \
        test_destroy_queue_on_disconnect (bind_address);                       \
    }

TEST_SUITE (inproc, "inproc://a")
TEST_SUITE (tcp, "tcp://127.0.0.1:*")

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_fair_queue_in_tcp);
    RUN_TEST (test_fair_queue_in_inproc);
    // TODO commented out until libzmq implements this properly
    // RUN_TEST (test_destroy_queue_on_disconnect_tcp);
    // RUN_TEST (test_destroy_queue_on_disconnect_inproc);
    return UNITY_END ();
}
