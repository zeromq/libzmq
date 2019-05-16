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

void create_inproc_client_server_pair (void **server_, void **client_)
{
    *server_ = test_context_socket (ZMQ_SERVER);
    *client_ = test_context_socket (ZMQ_CLIENT);

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_bind (*server_, "inproc://test-client-server"));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_connect (*client_, "inproc://test-client-server"));
}

void send_sndmore_expect_failure (void *socket_)
{
    int rc = zmq_send (socket_, "X", 1, ZMQ_SNDMORE);
    TEST_ASSERT_EQUAL_INT (-1, rc);
    TEST_ASSERT_EQUAL_INT (EINVAL, errno);
}

void test_client_sndmore_fails ()
{
    void *server, *client;
    create_inproc_client_server_pair (&server, &client);

    send_sndmore_expect_failure (client);

    test_context_socket_close (server);
    test_context_socket_close (client);
}

void test_server_sndmore_fails ()
{
    void *server, *client;
    create_inproc_client_server_pair (&server, &client);

    send_sndmore_expect_failure (server);

    test_context_socket_close (server);
    test_context_socket_close (client);
}

void test_routing_id ()
{
    void *server, *client;
    create_inproc_client_server_pair (&server, &client);

    send_string_expect_success (client, "X", 0);

    uint32_t routing_id;
    {
        zmq_msg_t msg;
        TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init (&msg));

        int rc = TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_recv (&msg, server, 0));
        TEST_ASSERT_EQUAL_INT (1, rc);

        routing_id = zmq_msg_routing_id (&msg);
        TEST_ASSERT_NOT_EQUAL (0, routing_id);

        TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg));
    }

    {
        zmq_msg_t msg;
        TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init_size (&msg, 1));

        char *data = (char *) zmq_msg_data (&msg);
        data[0] = 2;

        TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_set_routing_id (&msg, routing_id));

        int rc = zmq_msg_send (&msg, server, 0);
        TEST_ASSERT_EQUAL_INT (1, rc);
    }

    {
        zmq_msg_t msg;
        TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init (&msg));

        int rc = zmq_msg_recv (&msg, client, 0);
        TEST_ASSERT_EQUAL_INT (1, rc);

        routing_id = zmq_msg_routing_id (&msg);
        TEST_ASSERT_EQUAL_UINT32 (0, routing_id);

        TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg));
    }

    test_context_socket_close (server);
    test_context_socket_close (client);
}

int main (void)
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_client_sndmore_fails);
    RUN_TEST (test_server_sndmore_fails);
    RUN_TEST (test_routing_id);
    return UNITY_END ();
}
