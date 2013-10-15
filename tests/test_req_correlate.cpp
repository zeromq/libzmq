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

#include "testutil.hpp"

int main (void)
{
    setup_test_environment();
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    void *req = zmq_socket (ctx, ZMQ_REQ);
    assert (req);

    void *router = zmq_socket (ctx, ZMQ_ROUTER);
    assert (router);

    int enabled = 1;
    int rc = zmq_setsockopt (req, ZMQ_REQ_CORRELATE, &enabled, sizeof (int));
    assert (rc == 0);

    int rcvtimeo = 100;
    rc = zmq_setsockopt (req, ZMQ_RCVTIMEO, &rcvtimeo, sizeof (int));
    assert (rc == 0);

    rc = zmq_connect (req, "tcp://localhost:5555");
    assert (rc == 0);

    rc = zmq_bind (router, "tcp://127.0.0.1:5555");
    assert (rc == 0);

    // Send a multi-part request.
    s_send_seq (req, "ABC", "DEF", SEQ_END);

    zmq_msg_t msg;
    zmq_msg_init (&msg);

    // Receive peer identity
    rc = zmq_msg_recv (&msg, router, 0);
    assert (rc != -1);
    assert (zmq_msg_size (&msg) > 0);
    zmq_msg_t peer_id_msg;
    zmq_msg_init (&peer_id_msg);
    zmq_msg_copy (&peer_id_msg, &msg);

    int more = 0;
    size_t more_size = sizeof (more);
    rc = zmq_getsockopt (router, ZMQ_RCVMORE, &more, &more_size);
    assert (rc == 0);
    assert (more);

    // Receive request id 1
    rc = zmq_msg_recv (&msg, router, 0);
    assert (rc != -1);
    assert (zmq_msg_size (&msg) == sizeof(uint32_t));
    uint32_t req_id = *static_cast<uint32_t *> (zmq_msg_data (&msg));
    zmq_msg_t req_id_msg;
    zmq_msg_init (&req_id_msg);
    zmq_msg_copy (&req_id_msg, &msg);

    more = 0;
    more_size = sizeof (more);
    rc = zmq_getsockopt (router, ZMQ_RCVMORE, &more, &more_size);
    assert (rc == 0);
    assert (more);

    // Receive the rest.
    s_recv_seq (router, 0, "ABC", "DEF", SEQ_END);

    // Send back a bad reply: correct req id
    zmq_msg_copy (&msg, &peer_id_msg);
    rc = zmq_msg_send (&msg, router, ZMQ_SNDMORE);
    assert (rc != -1);
    zmq_msg_copy (&msg, &req_id_msg);
    rc = zmq_msg_send (&msg, router, 0);
    assert (rc != -1);

    // Send back a bad reply: wrong req id
    zmq_msg_copy (&msg, &peer_id_msg);
    rc = zmq_msg_send (&msg, router, ZMQ_SNDMORE);
    assert (rc != -1);
    uint32_t bad_req_id = req_id + 1;
    zmq_msg_init_data (&msg, &bad_req_id, sizeof (uint32_t), NULL, NULL);
    rc = zmq_msg_send (&msg, router, 0);
    assert (rc != -1);

    // Send back a bad reply: correct req id, 0
    zmq_msg_copy (&msg, &peer_id_msg);
    rc = zmq_msg_send (&msg, router, ZMQ_SNDMORE);
    assert (rc != -1);
    zmq_msg_copy (&msg, &req_id_msg);
    rc = zmq_msg_send (&msg, router, ZMQ_SNDMORE);
    assert (rc != -1);
    s_send_seq (router, 0, SEQ_END);

    // Send back a bad reply: correct req id, garbage
    zmq_msg_copy (&msg, &peer_id_msg);
    rc = zmq_msg_send (&msg, router, ZMQ_SNDMORE);
    assert (rc != -1);
    zmq_msg_copy (&msg, &req_id_msg);
    rc = zmq_msg_send (&msg, router, ZMQ_SNDMORE);
    assert (rc != -1);
    s_send_seq (router, "FOO", SEQ_END);

    // Send back a bad reply: wrong req id, 0
    zmq_msg_copy (&msg, &peer_id_msg);
    rc = zmq_msg_send (&msg, router, ZMQ_SNDMORE);
    assert (rc != -1);
    zmq_msg_init_data (&msg, &bad_req_id, sizeof (uint32_t), NULL, NULL);
    rc = zmq_msg_send (&msg, router, ZMQ_SNDMORE);
    assert (rc != -1);
    s_send_seq (router, 0, SEQ_END);

    // Send back a bad reply: correct req id, garbage, data
    zmq_msg_copy (&msg, &peer_id_msg);
    rc = zmq_msg_send (&msg, router, ZMQ_SNDMORE);
    assert (rc != -1);
    zmq_msg_copy (&msg, &req_id_msg);
    rc = zmq_msg_send (&msg, router, ZMQ_SNDMORE);
    assert (rc != -1);
    s_send_seq (router, "FOO", "DATA", SEQ_END);

    // Send back a bad reply: wrong req id, 0, data
    zmq_msg_copy (&msg, &peer_id_msg);
    rc = zmq_msg_send (&msg, router, ZMQ_SNDMORE);
    assert (rc != -1);
    zmq_msg_init_data (&msg, &bad_req_id, sizeof (uint32_t), NULL, NULL);
    rc = zmq_msg_send (&msg, router, ZMQ_SNDMORE);
    assert (rc != -1);
    s_send_seq (router, 0, "DATA", SEQ_END);

    // Send back a good reply.
    zmq_msg_copy (&msg, &peer_id_msg);
    rc = zmq_msg_send (&msg, router, ZMQ_SNDMORE);
    assert (rc != -1);
    zmq_msg_copy (&msg, &req_id_msg);
    rc = zmq_msg_send (&msg, router, ZMQ_SNDMORE);
    assert (rc != -1);
    s_send_seq (router, 0, "GHI", SEQ_END);

    // Receive reply. If any of the other messages got through, we wouldn't see
    // this particular data.
    s_recv_seq (req, "GHI", SEQ_END);

    rc = zmq_msg_close (&msg);
    assert (rc == 0);

    rc = zmq_msg_close (&peer_id_msg);
    assert (rc == 0);

    rc = zmq_msg_close (&req_id_msg);
    assert (rc == 0);

    close_zero_linger (req);
    close_zero_linger (router);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    return 0;
}
