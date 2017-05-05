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

static void bounce (void *socket)
{
    int more;
    size_t more_size = sizeof (more);
    do {
        zmq_msg_t recv_part, sent_part;
        int rc = zmq_msg_init (&recv_part);
        assert (rc == 0);

        rc = zmq_msg_recv (&recv_part, socket, 0);
        assert (rc != -1);

        rc = zmq_getsockopt (socket, ZMQ_RCVMORE, &more, &more_size);
        assert (rc == 0);

        zmq_msg_init (&sent_part);
        zmq_msg_copy (&sent_part, &recv_part);

        rc = zmq_msg_send (&sent_part, socket, more ? ZMQ_SNDMORE : 0);
        assert (rc != -1);

        zmq_msg_close (&recv_part);
    } while (more);
}

int main (void)
{
    setup_test_environment ();
    size_t len = MAX_SOCKET_STRING;
    char my_endpoint[MAX_SOCKET_STRING];
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    void *req = zmq_socket (ctx, ZMQ_REQ);
    assert (req);

    int enabled = 1;
    int rc = zmq_setsockopt (req, ZMQ_REQ_RELAXED, &enabled, sizeof (int));
    assert (rc == 0);

    rc = zmq_setsockopt (req, ZMQ_REQ_CORRELATE, &enabled, sizeof (int));
    assert (rc == 0);

    rc = zmq_bind (req, "tcp://127.0.0.1:*");
    assert (rc == 0);
    rc = zmq_getsockopt (req, ZMQ_LAST_ENDPOINT, my_endpoint, &len);
    assert (rc == 0);

    const size_t services = 5;
    void *rep [services];
    for (size_t peer = 0; peer < services; peer++) {
        rep [peer] = zmq_socket (ctx, ZMQ_REP);
        assert (rep [peer]);

        int timeout = 500;
        rc = zmq_setsockopt (rep [peer], ZMQ_RCVTIMEO, &timeout, sizeof (int));
        assert (rc == 0);

        rc = zmq_connect (rep [peer], my_endpoint);
        assert (rc == 0);
    }
    //  We have to give the connects time to finish otherwise the requests
    //  will not properly round-robin. We could alternatively connect the
    //  REQ sockets to the REP sockets.
    msleep (SETTLE_TIME);

    //  Case 1: Second send() before a reply arrives in a pipe.

    //  Send a request, ensure it arrives, don't send a reply
    s_send_seq (req, "A", "B", SEQ_END);
    s_recv_seq (rep [0], "A", "B", SEQ_END);

    //  Send another request on the REQ socket
    s_send_seq (req, "C", "D", SEQ_END);
    s_recv_seq (rep [1], "C", "D", SEQ_END);

    //  Send a reply to the first request - that should be discarded by the REQ
    s_send_seq (rep [0], "WRONG", SEQ_END);

    //  Send the expected reply
    s_send_seq (rep [1], "OK", SEQ_END);
    s_recv_seq (req, "OK", SEQ_END);


    //  Another standard req-rep cycle, just to check
    s_send_seq (req, "E", SEQ_END);
    s_recv_seq (rep [2], "E", SEQ_END);
    s_send_seq (rep [2], "F", "G", SEQ_END);
    s_recv_seq (req, "F", "G", SEQ_END);


    //  Case 2: Second send() after a reply is already in a pipe on the REQ.

    //  Send a request, ensure it arrives, send a reply
    s_send_seq (req, "H", SEQ_END);
    s_recv_seq (rep [3], "H", SEQ_END);
    s_send_seq (rep [3], "BAD", SEQ_END);

    //  Wait for message to be there.
    msleep (SETTLE_TIME);

    //  Without receiving that reply, send another request on the REQ socket
    s_send_seq (req, "I", SEQ_END);
    s_recv_seq (rep [4], "I", SEQ_END);

    //  Send the expected reply
    s_send_seq (rep [4], "GOOD", SEQ_END);
    s_recv_seq (req, "GOOD", SEQ_END);

    //  Case 3: Check issue #1690. Two send() in a row should not close the
    //  communication pipes. For example pipe from req to rep[0] should not be
    //  closed after executing Case 1. So rep[0] should be the next to receive,
    //  not rep[1].
    s_send_seq (req, "J", SEQ_END);
    s_recv_seq (rep [0], "J", SEQ_END);

    close_zero_linger (req);
    for (size_t peer = 0; peer < services; peer++)
        close_zero_linger (rep [peer]);

    //  Wait for disconnects.
    msleep (SETTLE_TIME);

    //  Case 4: Check issue #1695. As messages may pile up before a responder
    //  is available, we check that responses to messages other than the last
    //  sent one are correctly discarded by the REQ pipe

    //  Setup REQ socket as client
    req = zmq_socket (ctx, ZMQ_REQ);
    assert (req);

    rc = zmq_setsockopt (req, ZMQ_REQ_RELAXED, &enabled, sizeof (int));
    assert (rc == 0);

    rc = zmq_setsockopt (req, ZMQ_REQ_CORRELATE, &enabled, sizeof (int));
    assert (rc == 0);

    rc = zmq_connect (req, ENDPOINT_0);
    assert (rc == 0);

    //  Setup ROUTER socket as server but do not bind it just yet
    void *router = zmq_socket (ctx, ZMQ_ROUTER);
    assert (router);

    //  Send two requests
    s_send_seq (req, "TO_BE_DISCARDED", SEQ_END);
    s_send_seq (req, "TO_BE_ANSWERED", SEQ_END);

    //  Bind server allowing it to receive messages
    rc = zmq_bind (router, ENDPOINT_0);
    assert (rc == 0);

    //  Read the two messages and send them back as is
    bounce (router);
    bounce (router);

    //  Read the expected correlated reply. As the ZMQ_REQ_CORRELATE is active,
    //  the expected answer is "TO_BE_ANSWERED", not "TO_BE_DISCARDED".
    s_recv_seq (req, "TO_BE_ANSWERED", SEQ_END);

    close_zero_linger (req);
    close_zero_linger (router);

    //  Wait for disconnects.
    msleep (SETTLE_TIME);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    return 0 ;
}
