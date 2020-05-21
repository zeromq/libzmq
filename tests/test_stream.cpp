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

#include <string.h>

SETUP_TEARDOWN_TESTCONTEXT

//  ZMTP protocol greeting structure

typedef uint8_t byte;
typedef struct
{
    byte signature[10]; //  0xFF 8*0x00 0x7F
    byte version[2];    //  0x03 0x01 for ZMTP/3.1
    byte mechanism[20]; //  "NULL"
    byte as_server;
    byte filler[31];
} zmtp_greeting_t;

#define ZMTP_DEALER 5 //  Socket type constants

//  This is a greeting matching what 0MQ will send us; note the
//  8-byte size is set to 1 for backwards compatibility

static zmtp_greeting_t greeting = {
  {0xFF, 0, 0, 0, 0, 0, 0, 0, 1, 0x7F}, {3, 1}, {'N', 'U', 'L', 'L'}, 0, {0}};

static void test_stream_to_dealer ()
{
    int rc;
    char my_endpoint[MAX_SOCKET_STRING];

    //  We'll be using this socket in raw mode
    void *stream = test_context_socket (ZMQ_STREAM);

    int zero = 0;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (stream, ZMQ_LINGER, &zero, sizeof (zero)));
    int enabled = 1;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (stream, ZMQ_STREAM_NOTIFY, &enabled, sizeof (enabled)));
    bind_loopback_ipv4 (stream, my_endpoint, sizeof my_endpoint);

    //  We'll be using this socket as the other peer
    void *dealer = test_context_socket (ZMQ_DEALER);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (dealer, ZMQ_LINGER, &zero, sizeof (zero)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (dealer, my_endpoint));

    //  Send a message on the dealer socket
    send_string_expect_success (dealer, "Hello", 0);

    //  Connecting sends a zero message
    //  First frame is routing id
    zmq_msg_t routing_id;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init (&routing_id));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_recv (&routing_id, stream, 0));
    TEST_ASSERT_TRUE (zmq_msg_more (&routing_id));

    //  Verify the existence of Peer-Address metadata
    char const *peer_address = zmq_msg_gets (&routing_id, "Peer-Address");
    TEST_ASSERT_NOT_NULL (peer_address);
    TEST_ASSERT_EQUAL_STRING ("127.0.0.1", peer_address);

    //  Second frame is zero
    byte buffer[255];
    TEST_ASSERT_EQUAL_INT (
      0, TEST_ASSERT_SUCCESS_ERRNO (zmq_recv (stream, buffer, 255, 0)));

    //  Verify the existence of Peer-Address metadata
    peer_address = zmq_msg_gets (&routing_id, "Peer-Address");
    TEST_ASSERT_NOT_NULL (peer_address);
    TEST_ASSERT_EQUAL_STRING ("127.0.0.1", peer_address);

    //  Real data follows
    //  First frame is routing id
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_recv (&routing_id, stream, 0));
    TEST_ASSERT_TRUE (zmq_msg_more (&routing_id));

    //  Verify the existence of Peer-Address metadata
    peer_address = zmq_msg_gets (&routing_id, "Peer-Address");
    TEST_ASSERT_NOT_NULL (peer_address);
    TEST_ASSERT_EQUAL_STRING ("127.0.0.1", peer_address);

    //  Second frame is greeting signature
    recv_array_expect_success (stream, greeting.signature, 0);

    //  Send our own protocol greeting
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_send (&routing_id, stream, ZMQ_SNDMORE));
    TEST_ASSERT_EQUAL_INT (
      sizeof (greeting), TEST_ASSERT_SUCCESS_ERRNO (
                           zmq_send (stream, &greeting, sizeof (greeting), 0)));

    //  Now we expect the data from the DEALER socket
    //  We want the rest of greeting along with the Ready command
    int bytes_read = 0;
    while (bytes_read < 97) {
        //  First frame is the routing id of the connection (each time)
        TEST_ASSERT_GREATER_THAN_INT (
          0, TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_recv (&routing_id, stream, 0)));
        TEST_ASSERT_TRUE (zmq_msg_more (&routing_id));
        //  Second frame contains the next chunk of data
        TEST_ASSERT_SUCCESS_ERRNO (
          rc = zmq_recv (stream, buffer + bytes_read, 255 - bytes_read, 0));
        bytes_read += rc;
    }

    //  First two bytes are major and minor version numbers.
    TEST_ASSERT_EQUAL_INT (3, buffer[0]); //  ZMTP/3.1
    TEST_ASSERT_EQUAL_INT (1, buffer[1]);

    //  Mechanism is "NULL"
    TEST_ASSERT_EQUAL_INT8_ARRAY (buffer + 2,
                                  "NULL\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 20);
    TEST_ASSERT_EQUAL_INT8_ARRAY (buffer + 54, "\4\51\5READY", 8);
    TEST_ASSERT_EQUAL_INT8_ARRAY (buffer + 62, "\13Socket-Type\0\0\0\6DEALER",
                                  22);
    TEST_ASSERT_EQUAL_INT8_ARRAY (buffer + 84, "\10Identity\0\0\0\0", 13);

    //  Announce we are ready
    memcpy (buffer, "\4\51\5READY", 8);
    memcpy (buffer + 8, "\13Socket-Type\0\0\0\6ROUTER", 22);
    memcpy (buffer + 30, "\10Identity\0\0\0\0", 13);

    //  Send Ready command
    TEST_ASSERT_GREATER_THAN_INT (0, TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_send (
                                       &routing_id, stream, ZMQ_SNDMORE)));
    TEST_ASSERT_EQUAL_INT (
      43, TEST_ASSERT_SUCCESS_ERRNO (zmq_send (stream, buffer, 43, 0)));

    //  Now we expect the data from the DEALER socket
    //  First frame is, again, the routing id of the connection
    TEST_ASSERT_GREATER_THAN_INT (
      0, TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_recv (&routing_id, stream, 0)));
    TEST_ASSERT_TRUE (zmq_msg_more (&routing_id));

    //  Third frame contains Hello message from DEALER
    TEST_ASSERT_EQUAL_INT (7, TEST_ASSERT_SUCCESS_ERRNO (
                                zmq_recv (stream, buffer, sizeof buffer, 0)));

    //  Then we have a 5-byte message "Hello"
    TEST_ASSERT_EQUAL_INT (0, buffer[0]); //  Flags = 0
    TEST_ASSERT_EQUAL_INT (5, buffer[1]); //  Size = 5
    TEST_ASSERT_EQUAL_INT8_ARRAY (buffer + 2, "Hello", 5);

    //  Send "World" back to DEALER
    TEST_ASSERT_GREATER_THAN_INT (0, TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_send (
                                       &routing_id, stream, ZMQ_SNDMORE)));
    byte world[] = {0, 5, 'W', 'o', 'r', 'l', 'd'};
    TEST_ASSERT_EQUAL_INT (
      sizeof (world),
      TEST_ASSERT_SUCCESS_ERRNO (zmq_send (stream, world, sizeof (world), 0)));

    //  Expect response on DEALER socket
    recv_string_expect_success (dealer, "World", 0);

    //  Test large messages over STREAM socket
#define size 64000
    uint8_t msgout[size];
    memset (msgout, 0xAB, size);
    zmq_send (dealer, msgout, size, 0);

    uint8_t msgin[9 + size];
    memset (msgin, 0, 9 + size);
    bytes_read = 0;
    while (bytes_read < 9 + size) {
        //  Get routing id frame
        TEST_ASSERT_GREATER_THAN_INT (
          0, TEST_ASSERT_SUCCESS_ERRNO (zmq_recv (stream, buffer, 256, 0)));
        //  Get next chunk
        TEST_ASSERT_GREATER_THAN_INT (
          0,
          TEST_ASSERT_SUCCESS_ERRNO (rc = zmq_recv (stream, msgin + bytes_read,
                                                    9 + size - bytes_read, 0)));
        bytes_read += rc;
    }
    for (int byte_nbr = 0; byte_nbr < size; byte_nbr++) {
        TEST_ASSERT_EQUAL_UINT8 (0xAB, msgin[9 + byte_nbr]);
    }
    test_context_socket_close (dealer);
    test_context_socket_close (stream);
}


static void test_stream_to_stream ()
{
    char my_endpoint[MAX_SOCKET_STRING];
    //  Set-up our context and sockets

    void *server = test_context_socket (ZMQ_STREAM);
    int enabled = 1;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (server, ZMQ_STREAM_NOTIFY, &enabled, sizeof (enabled)));
    bind_loopback_ipv4 (server, my_endpoint, sizeof my_endpoint);

    void *client = test_context_socket (ZMQ_STREAM);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (client, ZMQ_STREAM_NOTIFY, &enabled, sizeof (enabled)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (client, my_endpoint));
    uint8_t id[256];
    uint8_t buffer[256];

    //  Connecting sends a zero message
    //  Server: First frame is routing id, second frame is zero
    TEST_ASSERT_GREATER_THAN_INT (
      0, TEST_ASSERT_SUCCESS_ERRNO (zmq_recv (server, id, 256, 0)));
    TEST_ASSERT_EQUAL_INT (
      0, TEST_ASSERT_SUCCESS_ERRNO (zmq_recv (server, buffer, 256, 0)));
    //  Client: First frame is routing id, second frame is zero
    TEST_ASSERT_GREATER_THAN_INT (
      0, TEST_ASSERT_SUCCESS_ERRNO (zmq_recv (client, id, 256, 0)));
    TEST_ASSERT_EQUAL_INT (
      0, TEST_ASSERT_SUCCESS_ERRNO (zmq_recv (client, buffer, 256, 0)));

    //  Sent HTTP request on client socket
    //  Get server routing id
    size_t id_size = sizeof id;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (client, ZMQ_ROUTING_ID, id, &id_size));
    //  First frame is server routing id
    TEST_ASSERT_EQUAL_INT ((int) id_size, TEST_ASSERT_SUCCESS_ERRNO (zmq_send (
                                            client, id, id_size, ZMQ_SNDMORE)));
    //  Second frame is HTTP GET request
    TEST_ASSERT_EQUAL_INT (
      7, TEST_ASSERT_SUCCESS_ERRNO (zmq_send (client, "GET /\n\n", 7, 0)));

    //  Get HTTP request; ID frame and then request
    TEST_ASSERT_GREATER_THAN_INT (
      0, TEST_ASSERT_SUCCESS_ERRNO (zmq_recv (server, id, 256, 0)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_recv (server, buffer, 256, 0));
    TEST_ASSERT_EQUAL_INT8_ARRAY (buffer, "GET /\n\n", 7);

    //  Send reply back to client
    char http_response[] = "HTTP/1.0 200 OK\r\n"
                           "Content-Type: text/plain\r\n"
                           "\r\n"
                           "Hello, World!";
    TEST_ASSERT_SUCCESS_ERRNO (zmq_send (server, id, id_size, ZMQ_SNDMORE));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_send (server, http_response, sizeof (http_response), ZMQ_SNDMORE));

    //  Send zero to close connection to client
    TEST_ASSERT_SUCCESS_ERRNO (zmq_send (server, id, id_size, ZMQ_SNDMORE));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_send (server, NULL, 0, ZMQ_SNDMORE));

    //  Get reply at client and check that it's complete
    TEST_ASSERT_GREATER_THAN_INT (
      0, TEST_ASSERT_SUCCESS_ERRNO (zmq_recv (client, id, 256, 0)));
    TEST_ASSERT_EQUAL_INT (
      sizeof http_response,
      TEST_ASSERT_SUCCESS_ERRNO (zmq_recv (client, buffer, 256, 0)));
    TEST_ASSERT_EQUAL_INT8_ARRAY (buffer, http_response,
                                  sizeof (http_response));

    // //  Get disconnection notification
    // FIXME: why does this block? Bug in STREAM disconnect notification?
    // id_size = zmq_recv (client, id, 256, 0);
    // assert (id_size > 0);
    // rc = zmq_recv (client, buffer, 256, 0);
    // assert (rc == 0);

    test_context_socket_close (server);
    test_context_socket_close (client);
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_stream_to_dealer);
    RUN_TEST (test_stream_to_stream);
    return UNITY_END ();
}
