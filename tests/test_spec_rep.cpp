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

void test_fair_queue_in (void *ctx)
{
    void *rep = zmq_socket (ctx, ZMQ_REP);
    assert (rep);

    int timeout = 100;
    int rc = zmq_setsockopt (rep, ZMQ_RCVTIMEO, &timeout, sizeof(int));
    assert (rc == 0);

    rc = zmq_bind (rep, "inproc://a");
    assert (rc == 0);

    const size_t N = 5;
    void *reqs[N];
    for (size_t i = 0; i < N; ++i)
    {
        reqs[i] = zmq_socket (ctx, ZMQ_REQ);
        assert (reqs[i]);

        rc = zmq_setsockopt (reqs[i], ZMQ_RCVTIMEO, &timeout, sizeof(int));
        assert (rc == 0);

        rc = zmq_connect (reqs[i], "inproc://a");
        assert (rc == 0);
    }

    s_send_seq (reqs[0], "A", SEQ_END);
    s_recv_seq (rep, "A", SEQ_END);
    s_send_seq (rep, "A", SEQ_END);
    s_recv_seq (reqs[0], "A", SEQ_END);

    s_send_seq (reqs[0], "A", SEQ_END);
    s_recv_seq (rep, "A", SEQ_END);
    s_send_seq (rep, "A", SEQ_END);
    s_recv_seq (reqs[0], "A", SEQ_END);

    // send N requests
    for (size_t i = 0; i < N; ++i)
    {
        char * str = strdup("A");
        str[0] += i;
        s_send_seq (reqs[i], str, SEQ_END);
        free (str);
    }

    // handle N requests
    for (size_t i = 0; i < N; ++i)
    {
        char * str = strdup("A");
        str[0] += i;
        s_recv_seq (rep, str, SEQ_END);
        s_send_seq (rep, str, SEQ_END);
        s_recv_seq (reqs[i], str, SEQ_END);
        free (str);
    }

    rc = zmq_close (rep);
    assert (rc == 0);

    for (size_t i = 0; i < N; ++i)
    {
        rc = zmq_close (reqs[i]);
        assert (rc == 0);
    }
}

void test_envelope (void *ctx)
{
    void *rep = zmq_socket (ctx, ZMQ_REP);
    assert (rep);

    int rc = zmq_bind (rep, "inproc://b");
    assert (rc == 0);

    void *dealer = zmq_socket (ctx, ZMQ_DEALER);
    assert (dealer);

    rc = zmq_connect (dealer, "inproc://b");
    assert (rc == 0);

    // minimal envelope
    s_send_seq (dealer, 0, "A", SEQ_END);
    s_recv_seq (rep, "A", SEQ_END);
    s_send_seq (rep, "A", SEQ_END);
    s_recv_seq (dealer, 0, "A", SEQ_END);

    // big envelope
    s_send_seq (dealer, "X", "Y", 0, "A", SEQ_END);
    s_recv_seq (rep, "A", SEQ_END);
    s_send_seq (rep, "A", SEQ_END);
    s_recv_seq (dealer, "X", "Y", 0, "A", SEQ_END);

    rc = zmq_close (rep);
    assert (rc == 0);

    rc = zmq_close (dealer);
    assert (rc == 0);
}

int main ()
{
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    // SHALL receive incoming messages from its peers using a fair-queuing
    // strategy.
    test_fair_queue_in (ctx);

    // For an incoming message:
    // SHALL remove and store the address envelope, including the delimiter.
    // SHALL pass the remaining data frames to its calling application.
    // SHALL wait for a single reply message from its calling application.
    // SHALL prepend the address envelope and delimiter.
    // SHALL deliver this message back to the originating peer.
    test_envelope (ctx);

    int rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    return 0 ;
}
