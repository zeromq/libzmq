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

//  ZMTP protocol greeting structure

typedef unsigned char byte;
typedef struct {
    byte signature [10];    //  0xFF 8*0x00 0x7F
    byte version [2];       //  0x03 0x00 for ZMTP/3.0
    byte mechanism [20];    //  "NULL"
    byte as_server;
    byte filler [31];
} zmtp_greeting_t;

#define ZMTP_DEALER  5      //  Socket type constants

//  This is a greeting matching what 0MQ will send us; note the
//  8-byte size is set to 1 for backwards compatibility

static zmtp_greeting_t
    greeting = { { 0xFF, 0, 0, 0, 0, 0, 0, 0, 1, 0x7F },
                 { 3, 0 },
                 { 'N', 'U', 'L', 'L'},
                 0,
                 { 0 }
    };

static void
test_stream_to_dealer (void)
{
    int rc;

    //  Set up our context and sockets
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    //  We'll be using this socket in raw mode
    void *stream = zmq_socket (ctx, ZMQ_STREAM);
    assert (stream);

    int zero = 0;
    rc = zmq_setsockopt (stream, ZMQ_LINGER, &zero, sizeof (zero));
    assert (rc == 0);
    int enabled = 1;
    rc = zmq_setsockopt (stream, ZMQ_STREAM_NOTIFY, &enabled, sizeof (enabled));
    assert (rc == 0);
    rc = zmq_bind (stream, "tcp://127.0.0.1:5556");
    assert (rc == 0);

    //  We'll be using this socket as the other peer
    void *dealer = zmq_socket (ctx, ZMQ_DEALER);
    assert (dealer);
    rc = zmq_setsockopt (dealer, ZMQ_LINGER, &zero, sizeof (zero));
    assert (rc == 0);
    rc = zmq_connect (dealer, "tcp://localhost:5556");

    //  Send a message on the dealer socket
    rc = zmq_send (dealer, "Hello", 5, 0);
    assert (rc == 5);

    //  Connecting sends a zero message
    //  First frame is identity
    zmq_msg_t identity;
    rc = zmq_msg_init (&identity);
    assert (rc == 0);
    rc = zmq_msg_recv (&identity, stream, 0);
    assert (rc > 0);
    assert (zmq_msg_more (&identity));

    //  Verify the existence of Peer-Address metadata
    char const *peer_address = zmq_msg_gets (&identity, "Peer-Address");
    assert (peer_address != 0);
    assert (streq (peer_address, "127.0.0.1"));

    //  Second frame is zero
    byte buffer [255];
    rc = zmq_recv (stream, buffer, 255, 0);
    assert (rc == 0);

    //  Verify the existence of Peer-Address metadata
    peer_address = zmq_msg_gets (&identity, "Peer-Address");
    assert (peer_address != 0);
    assert (streq (peer_address, "127.0.0.1"));

    //  Real data follows
    //  First frame is identity
    rc = zmq_msg_recv (&identity, stream, 0);
    assert (rc > 0);
    assert (zmq_msg_more (&identity));

    //  Verify the existence of Peer-Address metadata
    peer_address = zmq_msg_gets (&identity, "Peer-Address");
    assert (peer_address != 0);
    assert (streq (peer_address, "127.0.0.1"));

    //  Second frame is greeting signature
    rc = zmq_recv (stream, buffer, 255, 0);
    assert (rc == 10);
    assert (memcmp (buffer, greeting.signature, 10) == 0);

    //  Send our own protocol greeting
    rc = zmq_msg_send (&identity, stream, ZMQ_SNDMORE);
    assert (rc > 0);
    rc = zmq_send (stream, &greeting, sizeof (greeting), 0);
    assert (rc == sizeof (greeting));

    //  Now we expect the data from the DEALER socket
    //  We want the rest of greeting along with the Ready command
    int bytes_read = 0;
    while (bytes_read < 97) {
        //  First frame is the identity of the connection (each time)
        rc = zmq_msg_recv (&identity, stream, 0);
        assert (rc > 0);
        assert (zmq_msg_more (&identity));
        //  Second frame contains the next chunk of data
        rc = zmq_recv (stream, buffer + bytes_read, 255 - bytes_read, 0);
        assert (rc >= 0);
        bytes_read += rc;
    }

    //  First two bytes are major and minor version numbers.
    assert (buffer [0] == 3);       //  ZMTP/3.0
    assert (buffer [1] == 0);

    //  Mechanism is "NULL"
    assert (memcmp (buffer + 2, "NULL\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 20) == 0);
    assert (memcmp (buffer + 54, "\4\51\5READY", 8) == 0);
    assert (memcmp (buffer + 62, "\13Socket-Type\0\0\0\6DEALER", 22) == 0);
    assert (memcmp (buffer + 84, "\10Identity\0\0\0\0", 13) == 0);

    //  Announce we are ready
    memcpy (buffer, "\4\51\5READY", 8);
    memcpy (buffer + 8, "\13Socket-Type\0\0\0\6ROUTER", 22);
    memcpy (buffer + 30, "\10Identity\0\0\0\0", 13);

    //  Send Ready command
    rc = zmq_msg_send (&identity, stream, ZMQ_SNDMORE);
    assert (rc > 0);
    rc = zmq_send (stream, buffer, 43, 0);
    assert (rc == 43);

    //  Now we expect the data from the DEALER socket
    //  First frame is, again, the identity of the connection
    rc = zmq_msg_recv (&identity, stream, 0);
    assert (rc > 0);
    assert (zmq_msg_more (&identity));

    //  Third frame contains Hello message from DEALER
    rc = zmq_recv (stream, buffer, sizeof buffer, 0);
    assert (rc == 7);

    //  Then we have a 5-byte message "Hello"
    assert (buffer [0] == 0);       //  Flags = 0
    assert (buffer [1] == 5);       //  Size = 5
    assert (memcmp (buffer + 2, "Hello", 5) == 0);

    //  Send "World" back to DEALER
    rc = zmq_msg_send (&identity, stream, ZMQ_SNDMORE);
    assert (rc > 0);
    byte world [] = { 0, 5, 'W', 'o', 'r', 'l', 'd' };
    rc = zmq_send (stream, world, sizeof (world), 0);
    assert (rc == sizeof (world));

    //  Expect response on DEALER socket
    rc = zmq_recv (dealer, buffer, 255, 0);
    assert (rc == 5);
    assert (memcmp (buffer, "World", 5) == 0);

    //  Test large messages over STREAM socket
#   define size  64000
    uint8_t msgout [size];
    memset (msgout, 0xAB, size);
    zmq_send (dealer, msgout, size, 0);

    uint8_t msgin [9 + size];
    memset (msgin, 0, 9 + size);
    bytes_read = 0;
    while (bytes_read < 9 + size) {
        //  Get identity frame
        rc = zmq_recv (stream, buffer, 256, 0);
        assert (rc > 0);
        //  Get next chunk
        rc = zmq_recv (stream, msgin + bytes_read, 9 + size - bytes_read, 0);
        assert (rc > 0);
        bytes_read += rc;
    }
    int byte_nbr;
    for (byte_nbr = 0; byte_nbr < size; byte_nbr++) {
        if (msgin [9 + byte_nbr] != 0xAB)
            assert (false);
    }
    rc = zmq_close (dealer);
    assert (rc == 0);

    rc = zmq_close (stream);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);
}


static void
test_stream_to_stream (void)
{
    int rc;
    //  Set-up our context and sockets
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    void *server = zmq_socket (ctx, ZMQ_STREAM);
    assert (server);
    int enabled = 1;
    rc = zmq_setsockopt (server, ZMQ_STREAM_NOTIFY, &enabled, sizeof (enabled));
    assert (rc == 0);
    rc = zmq_bind (server, "tcp://127.0.0.1:9070");
    assert (rc == 0);

    void *client = zmq_socket (ctx, ZMQ_STREAM);
    assert (client);
    rc = zmq_setsockopt (client, ZMQ_STREAM_NOTIFY, &enabled, sizeof (enabled));
    assert (rc == 0);
    rc = zmq_connect (client, "tcp://localhost:9070");
    assert (rc == 0);
    uint8_t id [256];
    size_t id_size = 256;
    uint8_t buffer [256];

    //  Connecting sends a zero message
    //  Server: First frame is identity, second frame is zero
    id_size = zmq_recv (server, id, 256, 0);
    assert (id_size > 0);
    rc = zmq_recv (server, buffer, 256, 0);
    assert (rc == 0);
    //  Client: First frame is identity, second frame is zero
    id_size = zmq_recv (client, id, 256, 0);
    assert (id_size > 0);
    rc = zmq_recv (client, buffer, 256, 0);
    assert (rc == 0);

    //  Sent HTTP request on client socket
    //  Get server identity
    rc = zmq_getsockopt (client, ZMQ_IDENTITY, id, &id_size);
    assert (rc == 0);
    //  First frame is server identity
    rc = zmq_send (client, id, id_size, ZMQ_SNDMORE);
    assert (rc == (int) id_size);
    //  Second frame is HTTP GET request
    rc = zmq_send (client, "GET /\n\n", 7, 0);
    assert (rc == 7);

    //  Get HTTP request; ID frame and then request
    id_size = zmq_recv (server, id, 256, 0);
    assert (id_size > 0);
    rc = zmq_recv (server, buffer, 256, 0);
    assert (rc != -1);
    assert (memcmp (buffer, "GET /\n\n", 7) == 0);

    //  Send reply back to client
    char http_response [] =
        "HTTP/1.0 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "Hello, World!";
    rc = zmq_send (server, id, id_size, ZMQ_SNDMORE);
    assert (rc != -1);
    rc = zmq_send (server, http_response, sizeof (http_response), ZMQ_SNDMORE);
    assert (rc != -1);

    //  Send zero to close connection to client
    rc = zmq_send (server, id, id_size, ZMQ_SNDMORE);
    assert (rc != -1);
    rc = zmq_send (server, NULL, 0, ZMQ_SNDMORE);
    assert (rc != -1);

    //  Get reply at client and check that it's complete
    id_size = zmq_recv (client, id, 256, 0);
    assert (id_size > 0);
    rc = zmq_recv (client, buffer, 256, 0);
    assert (rc == sizeof (http_response));
    assert (memcmp (buffer, http_response, sizeof (http_response)) == 0);

    // //  Get disconnection notification
    // FIXME: why does this block? Bug in STREAM disconnect notification?
    // id_size = zmq_recv (client, id, 256, 0);
    // assert (id_size > 0);
    // rc = zmq_recv (client, buffer, 256, 0);
    // assert (rc == 0);

    rc = zmq_close (server);
    assert (rc == 0);

    rc = zmq_close (client);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);
}

int main (void)
{
    setup_test_environment();
    test_stream_to_dealer ();
    test_stream_to_stream ();
}
