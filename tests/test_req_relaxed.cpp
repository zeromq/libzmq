/*
    Copyright (c) 2007-2015 Contributors as noted in the AUTHORS file

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

int main (void)
{
    setup_test_environment();
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    void *req = zmq_socket (ctx, ZMQ_REQ);
    assert (req);

    int enabled = 1;
    int rc = zmq_setsockopt (req, ZMQ_REQ_RELAXED, &enabled, sizeof (int));
    assert (rc == 0);

    rc = zmq_setsockopt (req, ZMQ_REQ_CORRELATE, &enabled, sizeof (int));
    assert (rc == 0);

    rc = zmq_bind (req, "tcp://127.0.0.1:5555");
    assert (rc == 0);

    const size_t services = 5;
    void *rep [services];
    for (size_t peer = 0; peer < services; peer++) {
        rep [peer] = zmq_socket (ctx, ZMQ_REP);
        assert (rep [peer]);

        int timeout = 100;
        rc = zmq_setsockopt (rep [peer], ZMQ_RCVTIMEO, &timeout, sizeof (int));
        assert (rc == 0);

        rc = zmq_connect (rep [peer], "tcp://localhost:5555");
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

    // Wait for message to be there.
    rc = zmq_poll (0, 0, 100);
    assert (rc == 0);

    //  Without receiving that reply, send another request on the REQ socket
    s_send_seq (req, "I", SEQ_END);
    s_recv_seq (rep [4], "I", SEQ_END);

    //  Send the expected reply
    s_send_seq (rep [4], "GOOD", SEQ_END);
    s_recv_seq (req, "GOOD", SEQ_END);


    close_zero_linger (req);
    for (size_t peer = 0; peer < services; peer++)
        close_zero_linger (rep [peer]);

    // Wait for disconnects.
    rc = zmq_poll (0, 0, 100);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    return 0 ;
}
