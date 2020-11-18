/*
    Copyright (c) 2007-2018 Contributors as noted in the AUTHORS file

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

char connect_address[MAX_SOCKET_STRING];

// PUSH: SHALL route outgoing messages to connected peers using a
// round-robin strategy.
void test_push_round_robin_out (const char *bind_address_)
{
    void *push = test_context_socket (ZMQ_PUSH);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (push, bind_address_));
    size_t len = MAX_SOCKET_STRING;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (push, ZMQ_LAST_ENDPOINT, connect_address, &len));

    const size_t services = 5;
    void *pulls[services];
    for (size_t peer = 0; peer < services; ++peer) {
        pulls[peer] = test_context_socket (ZMQ_PULL);

        TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (pulls[peer], connect_address));
    }

    // Wait for connections.
    msleep (SETTLE_TIME);

    // Send 2N messages
    for (size_t peer = 0; peer < services; ++peer)
        s_send_seq (push, "ABC", SEQ_END);
    for (size_t peer = 0; peer < services; ++peer)
        s_send_seq (push, "DEF", SEQ_END);

    // Expect every PULL got one of each
    for (size_t peer = 0; peer < services; ++peer) {
        s_recv_seq (pulls[peer], "ABC", SEQ_END);
        s_recv_seq (pulls[peer], "DEF", SEQ_END);
    }

    test_context_socket_close_zero_linger (push);

    for (size_t peer = 0; peer < services; ++peer)
        test_context_socket_close_zero_linger (pulls[peer]);
}

// PULL: SHALL receive incoming messages from its peers using a fair-queuing
// strategy.
void test_pull_fair_queue_in (const char *bind_address_)
{
    void *pull = test_context_socket (ZMQ_PULL);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (pull, bind_address_));
    size_t len = MAX_SOCKET_STRING;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (pull, ZMQ_LAST_ENDPOINT, connect_address, &len));

    const unsigned char services = 5;
    void *pushs[services];
    for (unsigned char peer = 0; peer < services; ++peer) {
        pushs[peer] = test_context_socket (ZMQ_PUSH);

        TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (pushs[peer], connect_address));
    }

    // Wait for connections.
    msleep (SETTLE_TIME);

    int first_half = 0;
    int second_half = 0;

    // Send 2N messages
    for (unsigned char peer = 0; peer < services; ++peer) {
        char *str = strdup ("A");

        str[0] += peer;
        s_send_seq (pushs[peer], str, SEQ_END);
        first_half += str[0];

        str[0] += services;
        s_send_seq (pushs[peer], str, SEQ_END);
        second_half += str[0];

        free (str);
    }

    // Wait for data.
    msleep (SETTLE_TIME);

    zmq_msg_t msg;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init (&msg));

    // Expect to pull one from each first
    for (size_t peer = 0; peer < services; ++peer) {
        TEST_ASSERT_EQUAL_INT (
          2, TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_recv (&msg, pull, 0)));
        const char *str = static_cast<const char *> (zmq_msg_data (&msg));
        first_half -= str[0];
    }
    TEST_ASSERT_EQUAL_INT (0, first_half);

    // And then get the second batch
    for (size_t peer = 0; peer < services; ++peer) {
        TEST_ASSERT_EQUAL_INT (
          2, TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_recv (&msg, pull, 0)));
        const char *str = static_cast<const char *> (zmq_msg_data (&msg));
        second_half -= str[0];
    }
    TEST_ASSERT_EQUAL_INT (0, second_half);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg));

    test_context_socket_close_zero_linger (pull);

    for (size_t peer = 0; peer < services; ++peer)
        test_context_socket_close_zero_linger (pushs[peer]);
}

// PUSH: SHALL block on sending, or return a suitable error, when it has no
// available peers.
void test_push_block_on_send_no_peers (const char *bind_address_)
{
    void *sc = test_context_socket (ZMQ_PUSH);

    int timeout = 250;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sc, ZMQ_SNDTIMEO, &timeout, sizeof (timeout)));

    TEST_ASSERT_FAILURE_ERRNO (EAGAIN, zmq_send (sc, 0, 0, ZMQ_DONTWAIT));
    TEST_ASSERT_FAILURE_ERRNO (EAGAIN, zmq_send (sc, 0, 0, 0));

    test_context_socket_close (sc);
}

// PUSH and PULL: SHALL create this queue when a peer connects to it. If
// this peer disconnects, the socket SHALL destroy its queue and SHALL
// discard any messages it contains.
void test_destroy_queue_on_disconnect (const char *bind_address_)
{
    void *a = test_context_socket (ZMQ_PUSH);

    int hwm = 1;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (a, ZMQ_SNDHWM, &hwm, sizeof (hwm)));

    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (a, bind_address_));
    size_t len = MAX_SOCKET_STRING;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (a, ZMQ_LAST_ENDPOINT, connect_address, &len));

    void *b = test_context_socket (ZMQ_PULL);

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (b, ZMQ_RCVHWM, &hwm, sizeof (hwm)));

    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (b, connect_address));

    // Send two messages, one should be stuck in A's outgoing queue, the other
    // arrives at B.
    s_send_seq (a, "ABC", SEQ_END);
    s_send_seq (a, "DEF", SEQ_END);

    // Both queues should now be full, indicated by A blocking on send.
    TEST_ASSERT_FAILURE_ERRNO (EAGAIN, zmq_send (a, 0, 0, ZMQ_DONTWAIT));

    TEST_ASSERT_SUCCESS_ERRNO (zmq_disconnect (b, connect_address));

    // Disconnect may take time and need command processing.
    zmq_pollitem_t poller[2] = {{a, 0, 0, 0}, {b, 0, 0, 0}};
    TEST_ASSERT_EQUAL_INT (
      0, TEST_ASSERT_SUCCESS_ERRNO (zmq_poll (poller, 2, 100)));
    TEST_ASSERT_EQUAL_INT (
      0, TEST_ASSERT_SUCCESS_ERRNO (zmq_poll (poller, 2, 100)));

    zmq_msg_t msg;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init (&msg));

    // Can't receive old data on B.
    TEST_ASSERT_FAILURE_ERRNO (EAGAIN, zmq_msg_recv (&msg, b, ZMQ_DONTWAIT));

    // Sending fails.
    TEST_ASSERT_FAILURE_ERRNO (EAGAIN, zmq_send (a, 0, 0, ZMQ_DONTWAIT));

    // Reconnect B
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (b, connect_address));

    // Still can't receive old data on B.
    TEST_ASSERT_FAILURE_ERRNO (EAGAIN, zmq_msg_recv (&msg, b, ZMQ_DONTWAIT));

    // two messages should be sendable before the queues are filled up.
    s_send_seq (a, "ABC", SEQ_END);
    s_send_seq (a, "DEF", SEQ_END);

    TEST_ASSERT_FAILURE_ERRNO (EAGAIN, zmq_send (a, 0, 0, ZMQ_DONTWAIT));

    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg));

    test_context_socket_close_zero_linger (a);
    test_context_socket_close_zero_linger (b);
}

// PUSH and PULL: SHALL either receive or drop multipart messages atomically.
void test_push_multipart_atomic_drop (const char *bind_address_,
                                      const bool block_)
{
    int linger = 0;
    int hwm = 1;

    void *push = test_context_socket (ZMQ_PUSH);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (push, ZMQ_LINGER, &linger, sizeof (linger)));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (push, ZMQ_SNDHWM, &hwm, sizeof (hwm)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (push, bind_address_));
    size_t addr_len = MAX_SOCKET_STRING;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (push, ZMQ_LAST_ENDPOINT, connect_address, &addr_len));

    void *pull = test_context_socket (ZMQ_PULL);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (pull, ZMQ_LINGER, &linger, sizeof (linger)));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (pull, ZMQ_RCVHWM, &hwm, sizeof (hwm)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (pull, connect_address));

    // Wait for connections.
    msleep (SETTLE_TIME);

    int rc;
    zmq_msg_t msg_data;
    // A large message is needed to overrun the TCP buffers
    const size_t len = 16 * 1024 * 1024;
    size_t zmq_events_size = sizeof (int);
    int zmq_events;

    // Normal case - excercise the queues
    send_string_expect_success (push, "0", ZMQ_SNDMORE);
    send_string_expect_success (push, "0", ZMQ_SNDMORE);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init_size (&msg_data, len));
    memset (zmq_msg_data (&msg_data), 'a', len);
    TEST_ASSERT_EQUAL_INT (len, zmq_msg_send (&msg_data, push, 0));

    recv_string_expect_success (pull, "0", 0);
    recv_string_expect_success (pull, "0", 0);
    zmq_msg_init (&msg_data);
    TEST_ASSERT_EQUAL_INT (len, zmq_msg_recv (&msg_data, pull, 0));
    zmq_msg_close (&msg_data);

    // Fill the HWMs of sender and receiver, one message each
    send_string_expect_success (push, "1", 0);

    send_string_expect_success (push, "2", ZMQ_SNDMORE);
    send_string_expect_success (push, "2", ZMQ_SNDMORE);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init_size (&msg_data, len));
    memset (zmq_msg_data (&msg_data), 'b', len);
    TEST_ASSERT_EQUAL_INT (len, zmq_msg_send (&msg_data, push, 0));

    // Disconnect and simulate a poll (doesn't work on Windows) to
    // let the commands run and let the pipes start to be deallocated
    TEST_ASSERT_SUCCESS_ERRNO (zmq_disconnect (pull, connect_address));

    zmq_getsockopt (push, ZMQ_EVENTS, &zmq_events, &zmq_events_size);
    zmq_getsockopt (pull, ZMQ_EVENTS, &zmq_events, &zmq_events_size);
    msleep (SETTLE_TIME);
    zmq_getsockopt (push, ZMQ_EVENTS, &zmq_events, &zmq_events_size);
    zmq_getsockopt (pull, ZMQ_EVENTS, &zmq_events, &zmq_events_size);

    // Reconnect and immediately push a large message into the pipe,
    // if the problem is reproduced the pipe is in the process of being
    // terminated but still exists (state term_ack_sent) and had already
    // accepted the frame, so with the first frames already gone and
    // unreachable only the last is left, and is stuck in the lb.
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (pull, connect_address));

    send_string_expect_success (push, "3", ZMQ_SNDMORE);
    send_string_expect_success (push, "3", ZMQ_SNDMORE);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init_size (&msg_data, len));
    memset (zmq_msg_data (&msg_data), 'c', len);
    if (block_) {
        TEST_ASSERT_EQUAL_INT (len,
                               zmq_msg_send (&msg_data, push, ZMQ_SNDMORE));
    } else {
        rc = zmq_msg_send (&msg_data, push, ZMQ_SNDMORE | ZMQ_DONTWAIT);
        // inproc won't fail, much faster to connect/disconnect pipes than TCP
        if (rc == -1) {
            // at this point the new pipe is there and it works
            send_string_expect_success (push, "3", ZMQ_SNDMORE);
            send_string_expect_success (push, "3", ZMQ_SNDMORE);
            TEST_ASSERT_EQUAL_INT (len,
                                   zmq_msg_send (&msg_data, push, ZMQ_SNDMORE));
        }
    }
    send_string_expect_success (push, "3b", 0);

    zmq_getsockopt (push, ZMQ_EVENTS, &zmq_events, &zmq_events_size);
    zmq_getsockopt (pull, ZMQ_EVENTS, &zmq_events, &zmq_events_size);
    msleep (SETTLE_TIME);
    zmq_getsockopt (push, ZMQ_EVENTS, &zmq_events, &zmq_events_size);
    zmq_getsockopt (pull, ZMQ_EVENTS, &zmq_events, &zmq_events_size);

    send_string_expect_success (push, "5", ZMQ_SNDMORE);
    send_string_expect_success (push, "5", ZMQ_SNDMORE);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init_size (&msg_data, len));
    memset (zmq_msg_data (&msg_data), 'd', len);
    TEST_ASSERT_EQUAL_INT (len, zmq_msg_send (&msg_data, push, 0));

    // On very slow machines the message will not be lost, as it will
    // be sent when the new pipe is already in place, so avoid failing
    // and simply carry on as it would be very noisy otherwise.
    // Receive both to avoid leaking metadata.
    // If only the "5" message is received, the problem is reproduced, and
    // without the fix the first message received would be the last large
    // frame of "3".
    char buffer[2];
    rc =
      TEST_ASSERT_SUCCESS_ERRNO (zmq_recv (pull, buffer, sizeof (buffer), 0));
    TEST_ASSERT_EQUAL_INT (1, rc);
    TEST_ASSERT_TRUE (buffer[0] == '3' || buffer[0] == '5');
    if (buffer[0] == '3') {
        recv_string_expect_success (pull, "3", 0);
        zmq_msg_init (&msg_data);
        TEST_ASSERT_EQUAL_INT (len, zmq_msg_recv (&msg_data, pull, 0));
        zmq_msg_close (&msg_data);
        recv_string_expect_success (pull, "3b", 0);
        recv_string_expect_success (pull, "5", 0);
    }
    recv_string_expect_success (pull, "5", 0);
    zmq_msg_init (&msg_data);
    TEST_ASSERT_EQUAL_INT (len, zmq_msg_recv (&msg_data, pull, 0));
    zmq_msg_close (&msg_data);

    test_context_socket_close_zero_linger (pull);
    test_context_socket_close_zero_linger (push);
}

#define def_test_spec_pushpull(name, bind_address_)                            \
    void test_spec_pushpull_##name##_push_round_robin_out ()                   \
    {                                                                          \
        test_push_round_robin_out (bind_address_);                             \
    }                                                                          \
    void test_spec_pushpull_##name##_pull_fair_queue_in ()                     \
    {                                                                          \
        test_pull_fair_queue_in (bind_address_);                               \
    }                                                                          \
    void test_spec_pushpull_##name##_push_block_on_send_no_peers ()            \
    {                                                                          \
        test_push_block_on_send_no_peers (bind_address_);                      \
    }                                                                          \
    void test_spec_pushpull_##name##_destroy_queue_on_disconnect ()            \
    {                                                                          \
        test_destroy_queue_on_disconnect (bind_address_);                      \
    }                                                                          \
    void test_spec_pushpull_##name##_push_multipart_atomic_drop_block ()       \
    {                                                                          \
        test_push_multipart_atomic_drop (bind_address_, true);                 \
    }                                                                          \
    void test_spec_pushpull_##name##_push_multipart_atomic_drop_non_block ()   \
    {                                                                          \
        test_push_multipart_atomic_drop (bind_address_, false);                \
    }

def_test_spec_pushpull (inproc, "inproc://a")

  def_test_spec_pushpull (tcp, "tcp://127.0.0.1:*")

    int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_spec_pushpull_inproc_push_round_robin_out);
    RUN_TEST (test_spec_pushpull_tcp_push_round_robin_out);
    RUN_TEST (test_spec_pushpull_inproc_pull_fair_queue_in);
    RUN_TEST (test_spec_pushpull_tcp_pull_fair_queue_in);
    RUN_TEST (test_spec_pushpull_inproc_push_block_on_send_no_peers);
    RUN_TEST (test_spec_pushpull_tcp_push_block_on_send_no_peers);
    // TODO Tests disabled until libzmq does this properly
    //RUN_TEST (test_spec_pushpull_inproc_destroy_queue_on_disconnect);
    //RUN_TEST (test_spec_pushpull_tcp_destroy_queue_on_disconnect);
    RUN_TEST (test_spec_pushpull_inproc_push_multipart_atomic_drop_block);
    RUN_TEST (test_spec_pushpull_inproc_push_multipart_atomic_drop_non_block);
    RUN_TEST (test_spec_pushpull_tcp_push_multipart_atomic_drop_block);
    RUN_TEST (test_spec_pushpull_tcp_push_multipart_atomic_drop_non_block);
    return UNITY_END ();
}
