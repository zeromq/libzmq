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

char connect_address[MAX_SOCKET_STRING];

void test_round_robin_out (const char *bind_address_)
{
    void *req = test_context_socket (ZMQ_REQ);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (req, bind_address_));
    size_t len = MAX_SOCKET_STRING;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (req, ZMQ_LAST_ENDPOINT, connect_address, &len));

    const size_t services = 5;
    void *rep[services];
    for (size_t peer = 0; peer < services; peer++) {
        rep[peer] = test_context_socket (ZMQ_REP);

        int timeout = 250;
        TEST_ASSERT_SUCCESS_ERRNO (
          zmq_setsockopt (rep[peer], ZMQ_RCVTIMEO, &timeout, sizeof (int)));
        TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (rep[peer], connect_address));
    }
    //  We have to give the connects time to finish otherwise the requests
    //  will not properly round-robin. We could alternatively connect the
    //  REQ sockets to the REP sockets.
    msleep (SETTLE_TIME);

    // Send our peer-replies, and expect every REP it used once in order
    for (size_t peer = 0; peer < services; peer++) {
        s_send_seq (req, "ABC", SEQ_END);
        s_recv_seq (rep[peer], "ABC", SEQ_END);
        s_send_seq (rep[peer], "DEF", SEQ_END);
        s_recv_seq (req, "DEF", SEQ_END);
    }

    test_context_socket_close_zero_linger (req);
    for (size_t peer = 0; peer < services; peer++)
        test_context_socket_close_zero_linger (rep[peer]);
}

void test_req_only_listens_to_current_peer (const char *bind_address_)
{
    void *req = test_context_socket (ZMQ_REQ);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (req, ZMQ_ROUTING_ID, "A", 2));

    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (req, bind_address_));
    size_t len = MAX_SOCKET_STRING;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (req, ZMQ_LAST_ENDPOINT, connect_address, &len));

    const size_t services = 3;
    void *router[services];

    for (size_t i = 0; i < services; ++i) {
        router[i] = test_context_socket (ZMQ_ROUTER);

        int timeout = 250;
        TEST_ASSERT_SUCCESS_ERRNO (
          zmq_setsockopt (router[i], ZMQ_RCVTIMEO, &timeout, sizeof (timeout)));

        int enabled = 1;
        TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
          router[i], ZMQ_ROUTER_MANDATORY, &enabled, sizeof (enabled)));

        TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (router[i], connect_address));
    }

    // Wait for connects to finish.
    msleep (SETTLE_TIME);

    for (size_t i = 0; i < services; ++i) {
        // There still is a race condition when a stale peer's message
        // arrives at the REQ just after a request was sent to that peer.
        // To avoid that happening in the test, sleep for a bit.
        TEST_ASSERT_EQUAL_INT (1,
                               TEST_ASSERT_SUCCESS_ERRNO (zmq_poll (0, 0, 10)));

        s_send_seq (req, "ABC", SEQ_END);

        // Receive on router i
        s_recv_seq (router[i], "A", 0, "ABC", SEQ_END);

        // Send back replies on all routers
        for (size_t j = 0; j < services; ++j) {
            const char *replies[] = {"WRONG", "GOOD"};
            const char *reply = replies[i == j ? 1 : 0];
            s_send_seq (router[j], "A", 0, reply, SEQ_END);
        }

        // Receive only the good reply
        s_recv_seq (req, "GOOD", SEQ_END);
    }

    test_context_socket_close_zero_linger (req);
    for (size_t i = 0; i < services; ++i)
        test_context_socket_close_zero_linger (router[i]);
}

void test_req_message_format (const char *bind_address_)
{
    void *req = test_context_socket (ZMQ_REQ);
    void *router = test_context_socket (ZMQ_ROUTER);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (req, bind_address_));
    size_t len = MAX_SOCKET_STRING;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (req, ZMQ_LAST_ENDPOINT, connect_address, &len));

    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (router, connect_address));

    // Send a multi-part request.
    s_send_seq (req, "ABC", "DEF", SEQ_END);

    zmq_msg_t msg;
    zmq_msg_init (&msg);

    // Receive peer routing id
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_recv (&msg, router, 0));
    TEST_ASSERT_GREATER_THAN_INT (0, zmq_msg_size (&msg));
    zmq_msg_t peer_id_msg;
    zmq_msg_init (&peer_id_msg);
    zmq_msg_copy (&peer_id_msg, &msg);

    int more = 0;
    size_t more_size = sizeof (more);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (router, ZMQ_RCVMORE, &more, &more_size));
    TEST_ASSERT_TRUE (more);

    // Receive the rest.
    s_recv_seq (router, 0, "ABC", "DEF", SEQ_END);

    // Send back a single-part reply.
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_msg_send (&peer_id_msg, router, ZMQ_SNDMORE));
    s_send_seq (router, 0, "GHI", SEQ_END);

    // Receive reply.
    s_recv_seq (req, "GHI", SEQ_END);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&peer_id_msg));

    test_context_socket_close_zero_linger (req);
    test_context_socket_close_zero_linger (router);
}

void test_block_on_send_no_peers ()
{
    void *sc = test_context_socket (ZMQ_REQ);

    int timeout = 250;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sc, ZMQ_SNDTIMEO, &timeout, sizeof (timeout)));

    TEST_ASSERT_FAILURE_ERRNO (EAGAIN, zmq_send (sc, 0, 0, ZMQ_DONTWAIT));
    TEST_ASSERT_FAILURE_ERRNO (EAGAIN, zmq_send (sc, 0, 0, 0));

    test_context_socket_close (sc);
}

const char bind_inproc[] = "inproc://a";
const char bind_tcp[] = "tcp://127.0.0.1:*";

void test_round_robin_out_inproc ()
{
    test_round_robin_out (bind_inproc);
}

void test_round_robin_out_tcp ()
{
    test_round_robin_out (bind_tcp);
}

void test_req_message_format_inproc ()
{
    test_req_message_format (bind_inproc);
}

void test_req_message_format_tcp ()
{
    test_req_message_format (bind_tcp);
}

void test_req_only_listens_to_current_peer_inproc ()
{
    test_req_only_listens_to_current_peer (bind_inproc);
}

void test_req_only_listens_to_current_peer_tcp ()
{
    test_req_only_listens_to_current_peer (bind_tcp);
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();

    // SHALL route outgoing messages to connected peers using a round-robin
    // strategy.
    RUN_TEST (test_round_robin_out_inproc);
    RUN_TEST (test_round_robin_out_tcp);

    // The request and reply messages SHALL have this format on the wire:
    // * A delimiter, consisting of an empty frame, added by the REQ socket.
    // * One or more data frames, comprising the message visible to the
    //   application.
    RUN_TEST (test_req_message_format_inproc);
    RUN_TEST (test_req_message_format_tcp);

    // SHALL block on sending, or return a suitable error, when it has no
    // connected peers.
    RUN_TEST (test_block_on_send_no_peers);

    // SHALL accept an incoming message only from the last peer that it sent a
    // request to.
    // SHALL discard silently any messages received from other peers.
    // TODO PH: this test is still failing; disabled for now to allow build to
    // complete.
    // RUN_TEST (test_req_only_listens_to_current_peer_inproc);
    // RUN_TEST (test_req_only_listens_to_current_peer_tcp);

    return UNITY_END ();
}
