/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

#include <string.h>

SETUP_TEARDOWN_TESTCONTEXT

void test_stream_hwm_disconnect ()
{
    void *stream = test_context_socket (ZMQ_STREAM);
    char endpoint[MAX_SOCKET_STRING];

    //  Set a low Send High Water Mark to trigger the issue quickly
    int sndhwm = 3;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (stream, ZMQ_SNDHWM, &sndhwm, sizeof (sndhwm)));

    //  Bind the STREAM socket to a loopback address
    bind_loopback_ipv4 (stream, endpoint, sizeof (endpoint));

    //  Connect a raw TCP socket to the ZMQ_STREAM socket
    fd_t fd = connect_socket (endpoint);

    //  STREAM socket receives two frames on connection: 
    //  1. The routing ID of the new peer
    zmq_msg_t routing_id;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init (&routing_id));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_recv (&routing_id, stream, 0));
    
    //  Store routing ID for later use in disconnection
    size_t id_size = zmq_msg_size (&routing_id);
    void *id_data = zmq_msg_data (&routing_id);
    
    //  2. An empty frame (connection notification)
    TEST_ASSERT_TRUE (zmq_msg_more (&routing_id));
    zmq_msg_t empty;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init (&empty));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_recv (&empty, stream, 0));
    TEST_ASSERT_EQUAL_INT (0, zmq_msg_size (&empty));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&empty));

    //  Fill the outgoing pipe until it hits the High Water Mark.
    //  In ZMQ_STREAM, we send [Routing ID][Data].
    while (true) {
        //  Send Routing ID frame
        int rc = zmq_send (stream, id_data, id_size, ZMQ_DONTWAIT | ZMQ_SNDMORE);
        if (rc == -1)
            break;

        //  Send a large data frame to fill the buffer
        zmq_msg_t data;
        TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init_size (&data, 262144));
        rc = zmq_msg_send (&data, stream, ZMQ_DONTWAIT);
        TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&data));
        if (rc == -1)
            break;
    }

    //  Verify that we actually reached the HWM
    TEST_ASSERT_EQUAL_INT (EAGAIN, errno);

    //  TEST: Attempt to disconnect the client by sending the Routing ID 
    //  followed by a 0-byte payload.
    //  Before the fix, the first frame (Routing ID) would fail with EAGAIN.
    int rc = zmq_send (stream, id_data, id_size, ZMQ_DONTWAIT | ZMQ_SNDMORE);
    TEST_ASSERT_EQUAL_INT ((int) id_size, rc);

    //  The second frame (0-byte) should trigger the termination logic
    rc = zmq_send (stream, NULL, 0, ZMQ_DONTWAIT);
    TEST_ASSERT_EQUAL_INT (0, rc);

    //  Cleanup resources
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&routing_id));
    close (fd); // Standard POSIX close as seen in other test files
    test_context_socket_close (stream);
}

int main (int, char **)
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_stream_hwm_disconnect);
    return UNITY_END ();
}