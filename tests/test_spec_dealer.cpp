/*
    Copyright (c) 2007-2013 Contributors as noted in the AUTHORS file

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

#include <stdio.h>
#include <stdlib.h>
#include "testutil.hpp"

void test_round_robin_out (void *ctx)
{
    void *dealer = zmq_socket (ctx, ZMQ_DEALER);
    assert (dealer);

    int rc = zmq_bind (dealer, "inproc://b");
    assert (rc == 0);

    const size_t N = 5;
    void *rep[N];
    for (size_t i = 0; i < N; ++i)
    {
        rep[i] = zmq_socket (ctx, ZMQ_REP);
        assert (rep[i]);

        int timeout = 100;
        rc = zmq_setsockopt (rep[i], ZMQ_RCVTIMEO, &timeout, sizeof(int));
        assert (rc == 0);

        rc = zmq_connect (rep[i], "inproc://b");
        assert (rc == 0);
    }

    // Send N requests
    for (size_t i = 0; i < N; ++i)
    {
        s_send_seq (dealer, 0, "ABC", SEQ_END);
    }

    // Expect every REP got one message
    zmq_msg_t msg;
    zmq_msg_init (&msg);

    for (size_t i = 0; i < N; ++i)
    {
        s_recv_seq (rep[i], "ABC", SEQ_END);
    }

    rc = zmq_msg_close (&msg);
    assert (rc == 0);

    rc = zmq_close (dealer);
    assert (rc == 0);

    for (size_t i = 0; i < N; ++i)
    {
        rc = zmq_close (rep[i]);
        assert (rc == 0);
    }
}

void test_fair_queue_in (void *ctx)
{
    void *receiver = zmq_socket (ctx, ZMQ_DEALER);
    assert (receiver);

    int timeout = 100;
    int rc = zmq_setsockopt (receiver, ZMQ_RCVTIMEO, &timeout, sizeof(int));
    assert (rc == 0);

    rc = zmq_bind (receiver, "inproc://a");
    assert (rc == 0);

    const size_t N = 5;
    void *senders[N];
    for (size_t i = 0; i < N; ++i)
    {
        senders[i] = zmq_socket (ctx, ZMQ_DEALER);
        assert (senders[i]);

        rc = zmq_setsockopt (senders[i], ZMQ_RCVTIMEO, &timeout, sizeof(int));
        assert (rc == 0);

        rc = zmq_connect (senders[i], "inproc://a");
        assert (rc == 0);
    }

    zmq_msg_t msg;
    rc = zmq_msg_init (&msg);
    assert (rc == 0);

    s_send_seq (senders[0], "A", SEQ_END);
    s_recv_seq (receiver, "A", SEQ_END);

    s_send_seq (senders[0], "A", SEQ_END);
    s_recv_seq (receiver, "A", SEQ_END);

    // send N requests
    for (size_t i = 0; i < N; ++i)
    {
        char *str = strdup("A");
        str[0] += i;
        s_send_seq (senders[i], str, SEQ_END);
        free (str);
    }

    // handle N requests
    for (size_t i = 0; i < N; ++i)
    {
        char *str = strdup("A");
        str[0] += i;
        s_recv_seq (receiver, str, SEQ_END);
        free (str);
    }

    rc = zmq_msg_close (&msg);
    assert (rc == 0);

    rc = zmq_close (receiver);
    assert (rc == 0);

    for (size_t i = 0; i < N; ++i)
    {
        rc = zmq_close (senders[i]);
        assert (rc == 0);
    }
}

void test_destroy_queue_on_disconnect (void *ctx)
{
    void *A = zmq_socket (ctx, ZMQ_DEALER);
    assert (A);

    int rc = zmq_bind (A, "inproc://d");
    assert (rc == 0);

    void *B = zmq_socket (ctx, ZMQ_DEALER);
    assert (B);

    rc = zmq_connect (B, "inproc://d");
    assert (rc == 0);

    // Send a message in both directions
    s_send_seq (A, "ABC", SEQ_END);
    s_send_seq (B, "DEF", SEQ_END);

    rc = zmq_disconnect (B, "inproc://d");
    assert (rc == 0);

    // Disconnect may take time and need command processing.
    zmq_pollitem_t poller[2] = { { A, 0, 0, 0 }, { B, 0, 0, 0 } };
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
    rc = zmq_connect (B, "inproc://d");
    assert (rc == 0);

    rc = zmq_msg_recv (&msg, A, ZMQ_DONTWAIT);
    assert (rc == -1);
    assert (errno == EAGAIN);

    rc = zmq_msg_recv (&msg, B, ZMQ_DONTWAIT);
    assert (rc == -1);
    assert (errno == EAGAIN);

    rc = zmq_msg_close (&msg);
    assert (rc == 0);

    rc = zmq_close (A);
    assert (rc == 0);

    rc = zmq_close (B);
    assert (rc == 0);
}

void test_block_on_send_no_peers (void *ctx)
{
    void *sc = zmq_socket (ctx, ZMQ_DEALER);
    assert (sc);

    int timeout = 100;
    int rc = zmq_setsockopt (sc, ZMQ_SNDTIMEO, &timeout, sizeof(timeout));
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

int main ()
{
    void *ctx = zmq_ctx_new ();
    assert (ctx);

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
    test_destroy_queue_on_disconnect (ctx);

    int rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    return 0 ;
}
