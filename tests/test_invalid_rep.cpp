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
#include "testutil_unity.hpp"

SETUP_TEARDOWN_TESTCONTEXT

void test_invalid_rep ()
{
    //  Create REQ/ROUTER wiring.
    void *router_socket = test_context_socket (ZMQ_ROUTER);
    void *req_socket = test_context_socket (ZMQ_REQ);

    int linger = 0;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (router_socket, ZMQ_LINGER, &linger, sizeof (int)));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (req_socket, ZMQ_LINGER, &linger, sizeof (int)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (router_socket, "inproc://hi"));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (req_socket, "inproc://hi"));

    //  Initial request.
    send_string_expect_success (req_socket, "r", 0);

    //  Receive the request.
    char addr[32];
    int addr_size;
    char bottom[1];
    char body[1];
    TEST_ASSERT_SUCCESS_ERRNO (
      addr_size = zmq_recv (router_socket, addr, sizeof (addr), 0));
    TEST_ASSERT_EQUAL_INT (0, TEST_ASSERT_SUCCESS_ERRNO (zmq_recv (
                                router_socket, bottom, sizeof (bottom), 0)));
    TEST_ASSERT_EQUAL_INT (1, TEST_ASSERT_SUCCESS_ERRNO (zmq_recv (
                                router_socket, body, sizeof (body), 0)));

    //  Send invalid reply.
    TEST_ASSERT_EQUAL_INT (addr_size, TEST_ASSERT_SUCCESS_ERRNO (zmq_send (
                                        router_socket, addr, addr_size, 0)));

    //  Send valid reply.
    TEST_ASSERT_EQUAL_INT (
      addr_size, TEST_ASSERT_SUCCESS_ERRNO (
                   zmq_send (router_socket, addr, addr_size, ZMQ_SNDMORE)));
    TEST_ASSERT_EQUAL_INT (0, TEST_ASSERT_SUCCESS_ERRNO (zmq_send (
                                router_socket, bottom, 0, ZMQ_SNDMORE)));
    send_string_expect_success (router_socket, "b", 0);

    //  Check whether we've got the valid reply.
    recv_string_expect_success (req_socket, "b", 0);

    //  Tear down the wiring.
    test_context_socket_close (router_socket);
    test_context_socket_close (req_socket);
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_invalid_rep);
    return UNITY_END ();
}
