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

void test_req_correlate ()
{
    void *req = test_context_socket (ZMQ_REQ);
    void *router = test_context_socket (ZMQ_ROUTER);

    int enabled = 1;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (req, ZMQ_REQ_CORRELATE, &enabled, sizeof (int)));

    int rcvtimeo = 100;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (req, ZMQ_RCVTIMEO, &rcvtimeo, sizeof (int)));

    char my_endpoint[MAX_SOCKET_STRING];
    bind_loopback_ipv4 (router, my_endpoint, sizeof my_endpoint);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (req, my_endpoint));

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

    // Receive request id 1
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_recv (&msg, router, 0));
    TEST_ASSERT_EQUAL_UINT (sizeof (uint32_t), zmq_msg_size (&msg));
    const uint32_t req_id = *static_cast<uint32_t *> (zmq_msg_data (&msg));
    zmq_msg_t req_id_msg;
    zmq_msg_init (&req_id_msg);
    zmq_msg_copy (&req_id_msg, &msg);

    more = 0;
    more_size = sizeof (more);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (router, ZMQ_RCVMORE, &more, &more_size));
    TEST_ASSERT_TRUE (more);

    // Receive the rest.
    s_recv_seq (router, 0, "ABC", "DEF", SEQ_END);

    uint32_t bad_req_id = req_id + 1;

    // Send back a bad reply: wrong req id, 0, data
    zmq_msg_copy (&msg, &peer_id_msg);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_send (&msg, router, ZMQ_SNDMORE));
    zmq_msg_init_data (&msg, &bad_req_id, sizeof (uint32_t), NULL, NULL);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_send (&msg, router, ZMQ_SNDMORE));
    s_send_seq (router, 0, "DATA", SEQ_END);

    // Send back a good reply: good req id, 0, data
    zmq_msg_copy (&msg, &peer_id_msg);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_send (&msg, router, ZMQ_SNDMORE));
    zmq_msg_copy (&msg, &req_id_msg);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_send (&msg, router, ZMQ_SNDMORE));
    s_send_seq (router, 0, "GHI", SEQ_END);

    // Receive reply. If bad reply got through, we wouldn't see
    // this particular data.
    s_recv_seq (req, "GHI", SEQ_END);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&peer_id_msg));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&req_id_msg));

    test_context_socket_close_zero_linger (req);
    test_context_socket_close_zero_linger (router);
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_req_correlate);
    return UNITY_END ();
}
