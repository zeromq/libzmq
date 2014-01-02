/*
    Copyright (c) 2007-2014 Contributors as noted in the AUTHORS file

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "testutil.hpp"

const char *bind_address = 0;
const char *connect_address = 0;

void test_round_robin_out (void *ctx)
{
    void *dealer = zmq_socket (ctx, ZMQ_DEALER);
    assert (dealer);

    int rc = zmq_bind (dealer, bind_address);
    assert (rc == 0);

    const size_t services = 5;
    void *rep [services];
    for (size_t peer = 0; peer < services; ++peer) {
        rep [peer] = zmq_socket (ctx, ZMQ_REP);
        assert (rep [peer]);

        int timeout = 100;
        rc = zmq_setsockopt (rep [peer], ZMQ_RCVTIMEO, &timeout, sizeof (int));
        assert (rc == 0);

        rc = zmq_connect (rep [peer], connect_address);
        assert (rc == 0);
    }

    // Wait for connections.
    rc = zmq_poll (0, 0, 100);
    assert (rc == 0);

    // Send all requests
    for (size_t i = 0; i < services; ++i)
        s_send_seq (dealer, 0, "ABC", SEQ_END);

    // Expect every REP got one message
    zmq_msg_t msg;
    zmq_msg_init (&msg);

    for (size_t peer = 0; peer < services; ++peer)
        s_recv_seq (rep [peer], "ABC", SEQ_END);

    rc = zmq_msg_close (&msg);
    assert (rc == 0);

    close_zero_linger (dealer);

    for (size_t peer = 0; peer < services; ++peer)
        close_zero_linger (rep [peer]);

    // Wait for disconnects.
    rc = zmq_poll (0, 0, 100);
    assert (rc == 0);
}

void test_fair_queue_in (void *ctx)
{
    void *receiver = zmq_socket (ctx, ZMQ_DEALER);
    assert (receiver);

    int timeout = 100;
    int rc = zmq_setsockopt (receiver, ZMQ_RCVTIMEO, &timeout, sizeof (int));
    assert (rc == 0);

    rc = zmq_bind (receiver, bind_address);
    assert (rc == 0);

    const size_t services = 5;
    void *senders [services];
    for (size_t peer = 0; peer < services; ++peer) {
        senders [peer] = zmq_socket (ctx, ZMQ_DEALER);
        assert (senders [peer]);

        rc = zmq_setsockopt (senders [peer], ZMQ_RCVTIMEO, &timeout, sizeof (int));
        assert (rc == 0);

        rc = zmq_connect (senders [peer], connect_address);
        assert (rc == 0);
    }

    zmq_msg_t msg;
    rc = zmq_msg_init (&msg);
    assert (rc == 0);

    s_send_seq (senders [0], "A", SEQ_END);
    s_recv_seq (receiver, "A", SEQ_END);

    s_send_seq (senders [0], "A", SEQ_END);
    s_recv_seq (receiver, "A", SEQ_END);

    // send our requests
    for (size_t peer = 0; peer < services; ++peer)
        s_send_seq (senders [peer], "B", SEQ_END);

    // Wait for data.
    rc = zmq_poll (0, 0, 50);
    assert (rc == 0);

    // handle the requests
    for (size_t peer = 0; peer < services; ++peer)
        s_recv_seq (receiver, "B", SEQ_END);

    rc = zmq_msg_close (&msg);
    assert (rc == 0);

    close_zero_linger (receiver);

    for (size_t peer = 0; peer < services; ++peer)
        close_zero_linger (senders [peer]);

    // Wait for disconnects.
    rc = zmq_poll (0, 0, 100);
    assert (rc == 0);
}

void test_destroy_queue_on_disconnect (void *ctx)
{
    void *A = zmq_socket (ctx, ZMQ_DEALER);
    assert (A);

    int rc = zmq_bind (A, bind_address);
    assert (rc == 0);

    void *B = zmq_socket (ctx, ZMQ_DEALER);
    assert (B);

    rc = zmq_connect (B, connect_address);
    assert (rc == 0);

    // Send a message in both directions
    s_send_seq (A, "ABC", SEQ_END);
    s_send_seq (B, "DEF", SEQ_END);

    rc = zmq_disconnect (B, connect_address);
    assert (rc == 0);

    // Disconnect may take time and need command processing.
    zmq_pollitem_t poller [2] = { { A, 0, 0, 0 }, { B, 0, 0, 0 } };
    rc = zmq_poll (poller, 2, 100);
    assert (rc == 0);
    rc = zmq_poll (poller, 2, 100);
    assert (rc == 0);

    // No messages should be available, sending should fail.
    zmq_msg_t msg;
    zmq_msg_init (&msg);

    rc = zmq_send (A, 0, 0, ZMQ_DONTWAIT);
    assert (rc == -1);
    assert (errno == EAGAIN);

    rc = zmq_msg_recv (&msg, A, ZMQ_DONTWAIT);
    assert (rc == -1);
    assert (errno == EAGAIN);

    // After a reconnect of B, the messages should still be gone
    rc = zmq_connect (B, connect_address);
    assert (rc == 0);

    rc = zmq_msg_recv (&msg, A, ZMQ_DONTWAIT);
    assert (rc == -1);
    assert (errno == EAGAIN);

    rc = zmq_msg_recv (&msg, B, ZMQ_DONTWAIT);
    assert (rc == -1);
    assert (errno == EAGAIN);

    rc = zmq_msg_close (&msg);
    assert (rc == 0);

    close_zero_linger (A);
    close_zero_linger (B);

    // Wait for disconnects.
    rc = zmq_poll (0, 0, 100);
    assert (rc == 0);
}

void test_block_on_send_no_peers (void *ctx)
{
    void *sc = zmq_socket (ctx, ZMQ_DEALER);
    assert (sc);

    int timeout = 100;
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

int main (void)
{
    setup_test_environment();
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    const char *binds [] = { "inproc://a", "tcp://127.0.0.1:5555" };
    const char *connects [] = { "inproc://a", "tcp://localhost:5555" };

    for (int transports = 0; transports < 2; ++transports) {
        bind_address = binds [transports];
        connect_address = connects [transports];

        // SHALL route outgoing messages to available peers using a round-robin
        // strategy.
        test_round_robin_out (ctx);

        // SHALL receive incoming messages from its peers using a fair-queuing
        // strategy.
        test_fair_queue_in (ctx);

        // SHALL block on sending, or return a suitable error, when it has no connected peers.
        test_block_on_send_no_peers (ctx);

        // SHALL create a double queue when a peer connects to it. If this peer
        // disconnects, the DEALER socket SHALL destroy its double queue and SHALL
        // discard any messages it contains.
        // *** Test disabled until libzmq does this properly ***
        // test_destroy_queue_on_disconnect (ctx);
    }

    int rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    return 0 ;
}
