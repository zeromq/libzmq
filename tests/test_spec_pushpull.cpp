/*
    Copyright (c) 2007-2016 Contributors as noted in the AUTHORS file

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

const char *bind_address = 0;
const char *connect_address = 0;

void test_push_round_robin_out (void *ctx)
{
    void *push = zmq_socket (ctx, ZMQ_PUSH);
    assert (push);

    int rc = zmq_bind (push, bind_address);
    assert (rc == 0);

    const size_t services = 5;
    void *pulls [services];
    for (size_t peer = 0; peer < services; ++peer) {
        pulls [peer] = zmq_socket (ctx, ZMQ_PULL);
        assert (pulls [peer]);

        int timeout = 250;
        rc = zmq_setsockopt (pulls [peer], ZMQ_RCVTIMEO, &timeout, sizeof (int));
        assert (rc == 0);

        rc = zmq_connect (pulls [peer], connect_address);
        assert (rc == 0);
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
        s_recv_seq (pulls [peer], "ABC", SEQ_END);
        s_recv_seq (pulls [peer], "DEF", SEQ_END);
    }

    close_zero_linger (push);

    for (size_t peer = 0; peer < services; ++peer)
        close_zero_linger (pulls [peer]);

    // Wait for disconnects.
    msleep (SETTLE_TIME);
}

void test_pull_fair_queue_in (void *ctx)
{
    void *pull = zmq_socket (ctx, ZMQ_PULL);
    assert (pull);

    int rc = zmq_bind (pull, bind_address);
    assert (rc == 0);

    const size_t services = 5;
    void *pushs [services];
    for (size_t peer = 0; peer < services; ++peer)
    {
        pushs [peer] = zmq_socket (ctx, ZMQ_PUSH);
        assert (pushs [peer]);

        rc = zmq_connect (pushs [peer], connect_address);
        assert (rc == 0);
    }

    // Wait for connections.
    msleep (SETTLE_TIME);

    int first_half = 0;
    int second_half = 0;

    // Send 2N messages
    for (size_t peer = 0; peer < services; ++peer) {
        char *str = strdup("A");

        str [0] += peer;
        s_send_seq (pushs [peer], str, SEQ_END);
        first_half += str [0];

        str [0] += services;
        s_send_seq (pushs [peer], str, SEQ_END);
        second_half += str [0];

        free (str);
    }

    // Wait for data.
    msleep (SETTLE_TIME);

    zmq_msg_t msg;
    rc = zmq_msg_init (&msg);
    assert (rc == 0);

    // Expect to pull one from each first
    for (size_t peer = 0; peer < services; ++peer) {
        rc = zmq_msg_recv (&msg, pull, 0);
        assert (rc == 2);
        const char *str = (const char *)zmq_msg_data (&msg);
        first_half -= str [0];
    }
    assert (first_half == 0);

    // And then get the second batch
    for (size_t peer = 0; peer < services; ++peer) {
        rc = zmq_msg_recv (&msg, pull, 0);
        assert (rc == 2);
        const char *str = (const char *)zmq_msg_data (&msg);
        second_half -= str [0];
    }
    assert (second_half == 0);

    rc = zmq_msg_close (&msg);
    assert (rc == 0);

    close_zero_linger (pull);

    for (size_t peer = 0; peer < services; ++peer)
        close_zero_linger (pushs [peer]);

    // Wait for disconnects.
    msleep (SETTLE_TIME);
}

void test_push_block_on_send_no_peers (void *ctx)
{
    void *sc = zmq_socket (ctx, ZMQ_PUSH);
    assert (sc);

    int timeout = 250;
    int rc = zmq_setsockopt (sc, ZMQ_SNDTIMEO, &timeout, sizeof (timeout));
    assert (rc == 0);

    rc = zmq_send (sc, 0, 0, ZMQ_DONTWAIT);
    assert (rc == -1);
    assert (errno == EAGAIN);

    rc = zmq_send (sc, 0, 0, 0);
    assert (rc == -1);
    assert (errno == EAGAIN);

    rc = zmq_close (sc);
    assert (rc == 0);
}

void test_destroy_queue_on_disconnect (void *ctx)
{
    void *A = zmq_socket (ctx, ZMQ_PUSH);
    assert (A);

    int hwm = 1;
    int rc = zmq_setsockopt (A, ZMQ_SNDHWM, &hwm, sizeof (hwm));
    assert (rc == 0);

    rc = zmq_bind (A, bind_address);
    assert (rc == 0);

    void *B = zmq_socket (ctx, ZMQ_PULL);
    assert (B);

    rc = zmq_setsockopt (B, ZMQ_RCVHWM, &hwm, sizeof (hwm));
    assert (rc == 0);

    rc = zmq_connect (B, connect_address);
    assert (rc == 0);

    // Send two messages, one should be stuck in A's outgoing queue, the other
    // arrives at B.
    s_send_seq (A, "ABC", SEQ_END);
    s_send_seq (A, "DEF", SEQ_END);

    // Both queues should now be full, indicated by A blocking on send.
    rc = zmq_send (A, 0, 0, ZMQ_DONTWAIT);
    assert (rc == -1);
    assert (errno == EAGAIN);

    rc = zmq_disconnect (B, connect_address);
    assert (rc == 0);

    // Disconnect may take time and need command processing.
    zmq_pollitem_t poller [2] = { { A, 0, 0, 0 }, { B, 0, 0, 0 } };
    rc = zmq_poll (poller, 2, 100);
    assert (rc == 0);
    rc = zmq_poll (poller, 2, 100);
    assert (rc == 0);

    zmq_msg_t msg;
    rc = zmq_msg_init (&msg);
    assert (rc == 0);

    // Can't receive old data on B.
    rc = zmq_msg_recv (&msg, B, ZMQ_DONTWAIT);
    assert (rc == -1);
    assert (errno == EAGAIN);

    // Sending fails.
    rc = zmq_send (A, 0, 0, ZMQ_DONTWAIT);
    assert (rc == -1);
    assert (errno == EAGAIN);

    // Reconnect B
    rc = zmq_connect (B, connect_address);
    assert (rc == 0);

    // Still can't receive old data on B.
    rc = zmq_msg_recv (&msg, B, ZMQ_DONTWAIT);
    assert (rc == -1);
    assert (errno == EAGAIN);

    // two messages should be sendable before the queues are filled up.
    s_send_seq (A, "ABC", SEQ_END);
    s_send_seq (A, "DEF", SEQ_END);

    rc = zmq_send (A, 0, 0, ZMQ_DONTWAIT);
    assert (rc == -1);
    assert (errno == EAGAIN);

    rc = zmq_msg_close (&msg);
    assert (rc == 0);

    close_zero_linger (A);
    close_zero_linger (B);

    // Wait for disconnects.
    msleep (SETTLE_TIME);
}

int main (void)
{
    setup_test_environment();
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    const char *binds [] = { "inproc://a", "tcp://127.0.0.1:5555" };
    const char *connects [] = { "inproc://a", "tcp://localhost:5555" };

    for (int transport = 0; transport < 2; ++transport) {
        bind_address = binds [transport];
        connect_address = connects [transport];

        // PUSH: SHALL route outgoing messages to connected peers using a
        // round-robin strategy.
        test_push_round_robin_out (ctx);

        // PULL: SHALL receive incoming messages from its peers using a fair-queuing
        // strategy.
        test_pull_fair_queue_in (ctx);

        // PUSH: SHALL block on sending, or return a suitable error, when it has no
        // available peers.
        test_push_block_on_send_no_peers (ctx);

        // PUSH and PULL: SHALL create this queue when a peer connects to it. If
        // this peer disconnects, the socket SHALL destroy its queue and SHALL
        // discard any messages it contains.
        // *** Test disabled until libzmq does this properly ***
        // test_destroy_queue_on_disconnect (ctx);
    }

    int rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    return 0 ;
}
