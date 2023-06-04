/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

#include <string.h>

SETUP_TEARDOWN_TESTCONTEXT

void test_stream_exceeds_buffer ()
{
    const int msgsize = 8193;
    char sndbuf[msgsize] = "\xde\xad\xbe\xef";
    unsigned char rcvbuf[msgsize];
    char my_endpoint[MAX_SOCKET_STRING];

    int server_sock = bind_socket_resolve_port ("127.0.0.1", "0", my_endpoint);

    void *zsock = test_context_socket (ZMQ_STREAM);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (zsock, my_endpoint));

    int client_sock =
      TEST_ASSERT_SUCCESS_RAW_ERRNO (accept (server_sock, NULL, NULL));

    TEST_ASSERT_SUCCESS_RAW_ERRNO (close (server_sock));

    TEST_ASSERT_EQUAL_INT (msgsize, send (client_sock, sndbuf, msgsize, 0));

    zmq_msg_t msg;
    zmq_msg_init (&msg);

    int rcvbytes = 0;
    while (rcvbytes == 0) // skip connection notification, if any
    {
        TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_recv (&msg, zsock, 0)); // peerid
        TEST_ASSERT_TRUE (zmq_msg_more (&msg));
        rcvbytes = TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_recv (&msg, zsock, 0));
        TEST_ASSERT_FALSE (zmq_msg_more (&msg));
    }

    // for this test, we only collect the first chunk
    // since the corruption already occurs in the first chunk
    memcpy (rcvbuf, zmq_msg_data (&msg), zmq_msg_size (&msg));

    zmq_msg_close (&msg);
    test_context_socket_close (zsock);
    close (client_sock);

    TEST_ASSERT_GREATER_OR_EQUAL (4, rcvbytes);

    // notice that only the 1st byte gets corrupted
    TEST_ASSERT_EQUAL_UINT (0xef, rcvbuf[3]);
    TEST_ASSERT_EQUAL_UINT (0xbe, rcvbuf[2]);
    TEST_ASSERT_EQUAL_UINT (0xad, rcvbuf[1]);
    TEST_ASSERT_EQUAL_UINT (0xde, rcvbuf[0]);
}

int main ()
{
    UNITY_BEGIN ();
    RUN_TEST (test_stream_exceeds_buffer);
    return UNITY_END ();
}
