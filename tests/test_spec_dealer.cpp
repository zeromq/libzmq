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

// SHALL route outgoing messages to available peers using a round-robin
// strategy.
void test_round_robin_out (const char *bind_address_)
{
    void *dealer = test_context_socket (ZMQ_DEALER);

    char connect_address[MAX_SOCKET_STRING];
    test_bind (dealer, bind_address_, connect_address,
               sizeof (connect_address));

    const size_t services = 5;
    void *rep[services];
    for (size_t peer = 0; peer < services; ++peer) {
        rep[peer] = test_context_socket (ZMQ_REP);

        TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (rep[peer], connect_address));
    }

    // Wait for connections.
    msleep (SETTLE_TIME);

    // Send all requests
    for (size_t i = 0; i < services; ++i)
        s_send_seq (dealer, 0, "ABC", SEQ_END);

    // Expect every REP got one message
    zmq_msg_t msg;
    zmq_msg_init (&msg);

    for (size_t peer = 0; peer < services; ++peer)
        s_recv_seq (rep[peer], "ABC", SEQ_END);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg));

    test_context_socket_close_zero_linger (dealer);

    for (size_t peer = 0; peer < services; ++peer)
        test_context_socket_close_zero_linger (rep[peer]);
}

// SHALL receive incoming messages from its peers using a fair-queuing
// strategy.
void test_fair_queue_in (const char *bind_address_)
{
    void *receiver = test_context_socket (ZMQ_DEALER);

    char connect_address[MAX_SOCKET_STRING];
    test_bind (receiver, bind_address_, connect_address,
               sizeof (connect_address));

    const size_t services = 5;
    void *senders[services];
    for (size_t peer = 0; peer < services; ++peer) {
        senders[peer] = test_context_socket (ZMQ_DEALER);

        TEST_ASSERT_SUCCESS_ERRNO (
          zmq_connect (senders[peer], connect_address));
    }

    zmq_msg_t msg;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init (&msg));

    s_send_seq (senders[0], "A", SEQ_END);
    s_recv_seq (receiver, "A", SEQ_END);

    s_send_seq (senders[0], "A", SEQ_END);
    s_recv_seq (receiver, "A", SEQ_END);

    // send our requests
    for (size_t peer = 0; peer < services; ++peer)
        s_send_seq (senders[peer], "B", SEQ_END);

    // Wait for data.
    msleep (SETTLE_TIME);

    // handle the requests
    for (size_t peer = 0; peer < services; ++peer)
        s_recv_seq (receiver, "B", SEQ_END);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg));

    test_context_socket_close_zero_linger (receiver);

    for (size_t peer = 0; peer < services; ++peer)
        test_context_socket_close_zero_linger (senders[peer]);
}

// SHALL create a double queue when a peer connects to it. If this peer
// disconnects, the DEALER socket SHALL destroy its double queue and SHALL
// discard any messages it contains.
void test_destroy_queue_on_disconnect (const char *bind_address_)
{
    void *a = test_context_socket (ZMQ_DEALER);

    char connect_address[MAX_SOCKET_STRING];
    test_bind (a, bind_address_, connect_address, sizeof (connect_address));

    void *b = test_context_socket (ZMQ_DEALER);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (b, connect_address));

    // Send a message in both directions
    s_send_seq (a, "ABC", SEQ_END);
    s_send_seq (b, "DEF", SEQ_END);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_disconnect (b, connect_address));

    // Disconnect may take time and need command processing.
    zmq_pollitem_t poller[2] = {{a, 0, 0, 0}, {b, 0, 0, 0}};
    TEST_ASSERT_SUCCESS_ERRNO (zmq_poll (poller, 2, 100));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_poll (poller, 2, 100));

    // No messages should be available, sending should fail.
    zmq_msg_t msg;
    zmq_msg_init (&msg);

    TEST_ASSERT_FAILURE_ERRNO (EAGAIN, zmq_send (a, 0, 0, ZMQ_DONTWAIT));

    TEST_ASSERT_FAILURE_ERRNO (EAGAIN, zmq_msg_recv (&msg, a, ZMQ_DONTWAIT));

    // After a reconnect of B, the messages should still be gone
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (b, connect_address));

    TEST_ASSERT_FAILURE_ERRNO (EAGAIN, zmq_msg_recv (&msg, a, ZMQ_DONTWAIT));

    TEST_ASSERT_FAILURE_ERRNO (EAGAIN, zmq_msg_recv (&msg, b, ZMQ_DONTWAIT));

    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg));

    test_context_socket_close_zero_linger (a);
    test_context_socket_close_zero_linger (b);
}

// SHALL block on sending, or return a suitable error, when it has no connected peers.
void test_block_on_send_no_peers (const char *bind_address_)
{
    void *sc = test_context_socket (ZMQ_DEALER);

    int timeout = 250;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sc, ZMQ_SNDTIMEO, &timeout, sizeof (timeout)));

    TEST_ASSERT_FAILURE_ERRNO (EAGAIN, zmq_send (sc, 0, 0, ZMQ_DONTWAIT));
    TEST_ASSERT_FAILURE_ERRNO (EAGAIN, zmq_send (sc, 0, 0, 0));

    test_context_socket_close (sc);
}

#define TEST_CASES(name, bind_address)                                         \
    void test_round_robin_out_##name ()                                        \
    {                                                                          \
        test_round_robin_out (bind_address);                                   \
    }                                                                          \
    void test_fair_queue_in_##name () { test_fair_queue_in (bind_address); }   \
    void test_block_on_send_no_peers_##name ()                                 \
    {                                                                          \
        test_block_on_send_no_peers (bind_address);                            \
    }

TEST_CASES (inproc, "inproc://a")
TEST_CASES (tcp, "tcp://127.0.0.1:*")

int main (void)
{
    setup_test_environment ();

    UNITY_BEGIN ();

    RUN_TEST (test_round_robin_out_inproc);
    RUN_TEST (test_fair_queue_in_inproc);
    RUN_TEST (test_block_on_send_no_peers_inproc);

    RUN_TEST (test_round_robin_out_tcp);
    RUN_TEST (test_fair_queue_in_tcp);
    RUN_TEST (test_block_on_send_no_peers_tcp);

    // TODO *** Test disabled until libzmq does this properly ***
    // test_destroy_queue_on_disconnect (ctx);

    return UNITY_END ();
}
