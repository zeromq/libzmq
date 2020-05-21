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

void test_peer ()
{
    size_t len = MAX_SOCKET_STRING;
    char my_endpoint[MAX_SOCKET_STRING];

    void *peer1 = test_context_socket (ZMQ_PEER);
    bind_loopback (peer1, false, my_endpoint, len);

    void *peer2 = test_context_socket (ZMQ_PEER);
    uint32_t peer1_routing_id = zmq_connect_peer (peer2, my_endpoint);
    TEST_ASSERT_NOT_EQUAL (0, peer1_routing_id);

    {
        zmq_msg_t msg;
        TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init_size (&msg, 1));

        char *data = static_cast<char *> (zmq_msg_data (&msg));
        data[0] = 1;

        TEST_ASSERT_SUCCESS_ERRNO (
          zmq_msg_set_routing_id (&msg, peer1_routing_id));

        int rc = zmq_msg_send (&msg, peer2, 0);
        TEST_ASSERT_EQUAL_INT (1, rc);
    }

    uint32_t peer2_routing_id;
    {
        zmq_msg_t msg;
        TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init (&msg));

        int rc = TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_recv (&msg, peer1, 0));
        TEST_ASSERT_EQUAL_INT (1, rc);

        peer2_routing_id = zmq_msg_routing_id (&msg);
        TEST_ASSERT_NOT_EQUAL (0, peer2_routing_id);

        TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg));
    }

    {
        zmq_msg_t msg;
        TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init_size (&msg, 1));

        char *data = static_cast<char *> (zmq_msg_data (&msg));
        data[0] = 2;

        TEST_ASSERT_SUCCESS_ERRNO (
          zmq_msg_set_routing_id (&msg, peer2_routing_id));

        int rc = zmq_msg_send (&msg, peer1, 0);
        TEST_ASSERT_EQUAL_INT (1, rc);
    }

    {
        zmq_msg_t msg;
        TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init (&msg));

        int rc = zmq_msg_recv (&msg, peer2, 0);
        TEST_ASSERT_EQUAL_INT (1, rc);

        uint32_t routing_id = zmq_msg_routing_id (&msg);
        TEST_ASSERT_EQUAL_UINT32 (peer1_routing_id, routing_id);

        TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg));
    }

    test_context_socket_close (peer1);
    test_context_socket_close (peer2);
}

int main (void)
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_peer);
    return UNITY_END ();
}
