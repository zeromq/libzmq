/* SPDX-License-Identifier: MPL-2.0 */

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
