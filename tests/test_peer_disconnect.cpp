/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

#include <string.h>

SETUP_TEARDOWN_TESTCONTEXT

void test_peer_disconnect ()
{
    size_t len = MAX_SOCKET_STRING;
    char endpoint[MAX_SOCKET_STRING];

    // Create first peer and bind
    void *peer1 = test_context_socket (ZMQ_PEER);
    bind_loopback (peer1, false, endpoint, len);

    // Create second peer and connect atomically to get routing id
    void *peer2 = test_context_socket (ZMQ_PEER);
    uint32_t peer1_routing_id = zmq_connect_peer (peer2, endpoint);
    TEST_ASSERT_NOT_EQUAL (0, peer1_routing_id);

    // Send one byte from peer2 to peer1 with peer1's routing id
    {
        zmq_msg_t msg;
        TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init_size (&msg, 1));
        static_cast<char *> (zmq_msg_data (&msg))[0] = 'X';
        TEST_ASSERT_SUCCESS_ERRNO (
          zmq_msg_set_routing_id (&msg, peer1_routing_id));
        int rc = zmq_msg_send (&msg, peer2, 0);
        TEST_ASSERT_EQUAL_INT (1, rc);
    }

    // Receive on peer1; capture peer2's routing id
    uint32_t peer2_routing_id = 0;
    {
        zmq_msg_t msg;
        TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init (&msg));
        int rc = TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_recv (&msg, peer1, 0));
        TEST_ASSERT_EQUAL_INT (1, rc);
        peer2_routing_id = zmq_msg_routing_id (&msg);
        TEST_ASSERT_NOT_EQUAL (0, peer2_routing_id);
        TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg));
    }

    // Disconnect peer2 by its routing id on peer1
    TEST_ASSERT_SUCCESS_ERRNO (zmq_disconnect_peer (peer1, peer2_routing_id));

    // Attempt to send back to peer2 should fail with EHOSTUNREACH
    {
        zmq_msg_t msg;
        TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init_size (&msg, 5));
        memcpy (zmq_msg_data (&msg), "HELLO", 5);
        TEST_ASSERT_SUCCESS_ERRNO (
          zmq_msg_set_routing_id (&msg, peer2_routing_id));

        int rc = zmq_msg_send (&msg, peer1, 0);
        TEST_ASSERT_EQUAL_INT (-1, rc);
        TEST_ASSERT_EQUAL_INT (EHOSTUNREACH, errno);
        // On failure, close the message
        TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg));
    }

    test_context_socket_close (peer2);
    test_context_socket_close (peer1);
}

int main (void)
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_peer_disconnect);
    return UNITY_END ();
}
