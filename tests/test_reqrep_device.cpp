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

void test_roundtrip ()
{
    char endpoint1[MAX_SOCKET_STRING];
    char endpoint2[MAX_SOCKET_STRING];

    //  Create a req/rep device.
    void *dealer = test_context_socket (ZMQ_DEALER);
    bind_loopback_ipv4 (dealer, endpoint1, sizeof (endpoint1));

    void *router = test_context_socket (ZMQ_ROUTER);
    bind_loopback_ipv4 (router, endpoint2, sizeof (endpoint2));

    //  Create a worker.
    void *rep = test_context_socket (ZMQ_REP);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (rep, endpoint1));

    //  Create a client.
    void *req = test_context_socket (ZMQ_REQ);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (req, endpoint2));

    //  Send a request.
    send_string_expect_success (req, "ABC", ZMQ_SNDMORE);
    send_string_expect_success (req, "DEF", 0);

    //  Pass the request through the device.
    for (int i = 0; i != 4; i++) {
        zmq_msg_t msg;
        TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init (&msg));
        TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_recv (&msg, router, 0));
        int rcvmore;
        size_t sz = sizeof (rcvmore);
        TEST_ASSERT_SUCCESS_ERRNO (
          zmq_getsockopt (router, ZMQ_RCVMORE, &rcvmore, &sz));
        TEST_ASSERT_SUCCESS_ERRNO (
          zmq_msg_send (&msg, dealer, rcvmore ? ZMQ_SNDMORE : 0));
    }

    //  Receive the request.
    recv_string_expect_success (rep, "ABC", 0);
    int rcvmore;
    size_t sz = sizeof (rcvmore);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (rep, ZMQ_RCVMORE, &rcvmore, &sz));
    TEST_ASSERT_TRUE (rcvmore);
    recv_string_expect_success (rep, "DEF", 0);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (rep, ZMQ_RCVMORE, &rcvmore, &sz));
    TEST_ASSERT_FALSE (rcvmore);

    //  Send the reply.
    send_string_expect_success (rep, "GHI", ZMQ_SNDMORE);
    send_string_expect_success (rep, "JKL", 0);

    //  Pass the reply through the device.
    for (int i = 0; i != 4; i++) {
        zmq_msg_t msg;
        TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init (&msg));
        TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_recv (&msg, dealer, 0));
        int rcvmore;
        size_t sz = sizeof (rcvmore);
        TEST_ASSERT_SUCCESS_ERRNO (
          zmq_getsockopt (dealer, ZMQ_RCVMORE, &rcvmore, &sz));
        TEST_ASSERT_SUCCESS_ERRNO (
          zmq_msg_send (&msg, router, rcvmore ? ZMQ_SNDMORE : 0));
    }

    //  Receive the reply.
    recv_string_expect_success (req, "GHI", 0);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (req, ZMQ_RCVMORE, &rcvmore, &sz));
    TEST_ASSERT_TRUE (rcvmore);
    recv_string_expect_success (req, "JKL", 0);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (req, ZMQ_RCVMORE, &rcvmore, &sz));
    TEST_ASSERT_FALSE (rcvmore);

    //  Clean up.
    test_context_socket_close (req);
    test_context_socket_close (rep);
    test_context_socket_close (router);
    test_context_socket_close (dealer);
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_roundtrip);
    return UNITY_END ();
}
