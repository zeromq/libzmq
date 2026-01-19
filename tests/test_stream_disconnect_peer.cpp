/* SPDX-License-Identifier: MPL-2.0 */

#define ZMQ_BUILD_DRAFT_API

#include "testutil.hpp"
#include "testutil_unity.hpp"

#include <string.h>

#if defined ZMQ_HAVE_WINDOWS
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

SETUP_TEARDOWN_TESTCONTEXT

//  Helper to extract numeric host ID from the 5-byte ZMQ_STREAM frame [0x00][uint32]
static uint32_t extract_id (zmq_msg_t *msg_)
{
    TEST_ASSERT_EQUAL_INT (5, zmq_msg_size (msg_));
    const unsigned char *id_ptr = (const unsigned char *) zmq_msg_data (msg_);
    uint32_t net_id;
    memcpy (&net_id, id_ptr + 1, 4);
    return ntohl (net_id);
}

static void test_stream_disconnect_peer ()
{
    char my_endpoint[MAX_SOCKET_STRING];

    //  We'll be using this socket to test the surgical disconnect API
    void *stream = test_context_socket (ZMQ_STREAM);

    //  Set timeouts to prevent the test from hanging indefinitely on failure
    int timeout = 500;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (stream, ZMQ_SNDTIMEO, &timeout, sizeof (timeout)));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (stream, ZMQ_RCVTIMEO, &timeout, sizeof (timeout)));

    bind_loopback_ipv4 (stream, my_endpoint, sizeof (my_endpoint));

    //  Connect two distinct clients to test isolation and state reset
    fd_t fd_a = connect_socket (my_endpoint);
    fd_t fd_b = connect_socket (my_endpoint);

    zmq_msg_t msg;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init (&msg));

    //  Peer A Setup: Receive connection notification
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_recv (&msg, stream, 0));
    uint32_t id_a_numeric = extract_id (&msg);
    unsigned char id_a_raw[5];
    memcpy (id_a_raw, zmq_msg_data (&msg), 5);
    TEST_ASSERT_EQUAL_INT (
      0, TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_recv (&msg, stream, 0)));

    //  Peer B Setup: Receive connection notification
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_recv (&msg, stream, 0));
    uint32_t id_b_numeric = extract_id (&msg);
    unsigned char id_b_raw[5];
    memcpy (id_b_raw, zmq_msg_data (&msg), 5);
    TEST_ASSERT_EQUAL_INT (
      0, TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_recv (&msg, stream, 0)));

    //  Verify Peer IDs are unique
    TEST_ASSERT_NOT_EQUAL (id_a_numeric, id_b_numeric);

    // --- CASE 1: THE DIRTY RESET ---
    //  Start a multi-part message to Peer A.
    //  This locks the socket state machine (_more_out = true, _current_out = Pipe A).
    TEST_ASSERT_EQUAL_INT (5, zmq_send (stream, id_a_raw, 5, ZMQ_SNDMORE));

    //  Use the new API to surgically disconnect Peer A.
    //  This must force-reset the internal 'more' state and NULL the current pipe.
    TEST_ASSERT_SUCCESS_ERRNO (zmq_disconnect_peer (stream, id_a_numeric));
    msleep (SETTLE_TIME);

    //  Attempt to talk to Peer B immediately.
    //  If the reset failed, this would misroute the ID frame as data for Peer A.
    TEST_ASSERT_EQUAL_INT (5, zmq_send (stream, id_b_raw, 5, ZMQ_SNDMORE));
    TEST_ASSERT_EQUAL_INT (5, zmq_send (stream, "HELLO", 5, 0));

    //  Verify Peer B actually received the data via raw TCP
    char recv_buf[5];
    int bytes = recv (fd_b, recv_buf, 5, 0);
    TEST_ASSERT_EQUAL_INT (5, bytes);
    TEST_ASSERT_EQUAL_STRING_LEN ("HELLO", recv_buf, 5);

    // --- CASE 2: SURGICAL ISOLATION ---
    //  Verify Peer A is gone from the routing table; sending to it should fail.
    int rc = zmq_send (stream, id_a_raw, 5, ZMQ_SNDMORE);
    TEST_ASSERT_EQUAL_INT (-1, rc);
    TEST_ASSERT_EQUAL_INT (EHOSTUNREACH, errno);

    // --- CASE 3: INBOUND INTEGRITY ---
    //  Ensure Peer B can still send data to the server (FQ remains intact).
    const char *ping = "PING";
    send (fd_b, ping, 4, 0);
    msleep (SETTLE_TIME);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_recv (&msg, stream, 0));
    TEST_ASSERT_EQUAL_INT (id_b_numeric, extract_id (&msg));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_recv (&msg, stream, 0));
    TEST_ASSERT_EQUAL_STRING_LEN (ping, (char *) zmq_msg_data (&msg), 4);

    // --- CASE 4: ERROR HANDLING ---
    //  Attempt to disconnect a non-existent ID
    rc = zmq_disconnect_peer (stream, 0x12345678);
    TEST_ASSERT_EQUAL_INT (-1, rc);
    TEST_ASSERT_EQUAL_INT (EHOSTUNREACH, errno);

    //  Cleanup
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg));
    close (fd_a);
    close (fd_b);
    test_context_socket_close (stream);
}

int main (void)
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_stream_disconnect_peer);
    return UNITY_END ();
}