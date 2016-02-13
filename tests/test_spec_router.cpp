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

void test_fair_queue_in (void *ctx)
{
    void *receiver = zmq_socket (ctx, ZMQ_ROUTER);
    assert (receiver);

    int timeout = 250;
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

        char *str = strdup("A");
        str [0] += peer;
        rc = zmq_setsockopt (senders [peer], ZMQ_IDENTITY, str, 2);
        assert (rc == 0);
        free (str);

        rc = zmq_connect (senders [peer], connect_address);
        assert (rc == 0);
    }

    msleep (SETTLE_TIME);

    zmq_msg_t msg;
    rc = zmq_msg_init (&msg);
    assert (rc == 0);

    s_send_seq (senders [0], "M", SEQ_END);
    s_recv_seq (receiver, "A", "M", SEQ_END);

    s_send_seq (senders [0], "M", SEQ_END);
    s_recv_seq (receiver, "A", "M", SEQ_END);

    int sum = 0;

    // send N requests
    for (size_t peer = 0; peer < services; ++peer) {
        s_send_seq (senders [peer], "M", SEQ_END);
        sum += 'A' + peer;
    }

    assert (sum == services * 'A' + services * (services - 1) / 2);

    // handle N requests
    for (size_t peer = 0; peer < services; ++peer) {
        rc = zmq_msg_recv (&msg, receiver, 0);
        assert (rc == 2);
        const char *id = (const char *)zmq_msg_data (&msg);
        sum -= id [0];

        s_recv_seq (receiver, "M", SEQ_END);
    }

    assert (sum == 0);

    rc = zmq_msg_close (&msg);
    assert (rc == 0);

    close_zero_linger (receiver);

    for (size_t peer = 0; peer < services; ++peer)
        close_zero_linger (senders [peer]);

    // Wait for disconnects.
    msleep (SETTLE_TIME);
}

void test_destroy_queue_on_disconnect (void *ctx)
{
    void *A = zmq_socket (ctx, ZMQ_ROUTER);
    assert (A);

    int enabled = 1;
    int rc = zmq_setsockopt (A, ZMQ_ROUTER_MANDATORY, &enabled, sizeof (enabled));
    assert (rc == 0);

    rc = zmq_bind (A, bind_address);
    assert (rc == 0);

    void *B = zmq_socket (ctx, ZMQ_DEALER);
    assert (B);

    rc = zmq_setsockopt (B, ZMQ_IDENTITY, "B", 2);
    assert (rc == 0);

    rc = zmq_connect (B, connect_address);
    assert (rc == 0);

    // Wait for connection.
    msleep (SETTLE_TIME);

    // Send a message in both directions
    s_send_seq (A, "B", "ABC", SEQ_END);
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

    rc = zmq_send (A, "B", 2, ZMQ_SNDMORE | ZMQ_DONTWAIT);
    assert (rc == -1);
    assert (errno == EHOSTUNREACH);

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

        // SHALL receive incoming messages from its peers using a fair-queuing
        // strategy.
        test_fair_queue_in (ctx);

        // SHALL create a double queue when a peer connects to it. If this peer
        // disconnects, the ROUTER socket SHALL destroy its double queue and SHALL
        // discard any messages it contains.
        // *** Test disabled until libzmq does this properly ***
        // test_destroy_queue_on_disconnect (ctx);
    }

    int rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    return 0 ;
}
