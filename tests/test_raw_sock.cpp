/*
    Copyright (c) 2007-2013 iMatix Corporation
    Copyright (c) 2007-2012 Other contributors as noted in the AUTHORS file

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "../include/zmq.h"
#include <string.h>
#include <stdbool.h>
#undef NDEBUG
#include <assert.h>

//  ZMTP protocol greeting structure

typedef unsigned char byte;
typedef struct {
    byte signature [10];    //  0xFF 8*0x00 0x7F
    byte revision;          //  0x01 = ZMTP/2.0
    byte socktype;          //  Defined in ZMTP spec
    byte identity [2];      //  Empty message
} zmtp_greeting_t;

#define ZMTP_DEALER  5      //  Socket type constants
#define ZMTP_ROUTER  6

//  This is a greeting matching what 0MQ will send us; note the
//  8-byte size is set to 1 for backwards compatibility

static zmtp_greeting_t greeting
    = { { 0xFF, 0, 0, 0, 0, 0, 0, 0, 1, 0x7F }, 1, 0, { 0, 0 } };

int main (void)
{
    int rc;

    //  Set up our context and sockets
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    //  We'll be using this socket in raw mode
    void *router = zmq_socket (ctx, ZMQ_ROUTER);
    assert (router);

    int on = 1;
    rc = zmq_setsockopt (router, ZMQ_ROUTER_RAW, &on, sizeof (on));
    assert (rc == 0);
    int zero = 0;
    rc = zmq_setsockopt (router, ZMQ_LINGER, &zero, sizeof (zero));
    assert (rc == 0);
    rc = zmq_bind (router, "tcp://*:5555");
    assert (rc == 0);

    //  We'll be using this socket as the other peer
    void *dealer = zmq_socket (ctx, ZMQ_DEALER);
    assert (dealer);
    rc = zmq_setsockopt (dealer, ZMQ_LINGER, &zero, sizeof (zero));
    assert (rc == 0);
    rc = zmq_connect (dealer, "tcp://localhost:5555");

    //  Send a message on the dealer socket
    rc = zmq_send (dealer, "Hello", 5, 0);
    assert (rc == 5);

    //  First frame is identity
    zmq_msg_t identity;
    rc = zmq_msg_init (&identity);
    assert (rc == 0);
    rc = zmq_msg_recv (&identity, router, 0);
    assert (rc > 0);
    assert (zmq_msg_more (&identity));

    //  Second frame is greeting signature
    byte buffer [255];
    rc = zmq_recv (router, buffer, 255, 0);
    assert (rc == 10);
    assert (memcmp (buffer, greeting.signature, 10) == 0);

    //  Send our own protocol greeting
    rc = zmq_msg_send (&identity, router, ZMQ_SNDMORE);
    assert (rc > 0);
    greeting.socktype = ZMTP_ROUTER;
    rc = zmq_send (router, &greeting, sizeof (greeting), 0);
    assert (rc == sizeof (greeting));

    //  Now we expect the data from the DEALER socket
    //  First frame is, again, the identity of the connection
    rc = zmq_msg_recv (&identity, router, 0);
    assert (rc > 0);
    assert (zmq_msg_more (&identity));

    //  Second frame contains all remaining data from DEALER
    rc = zmq_recv (router, buffer, 255, 0);
    assert (rc == 11);

    //  First four bytes are [revision][socktype][identity]
    assert (buffer [0] == 1);       //  Revision = 1
    assert (buffer [1] == ZMTP_DEALER);

    //  Identity is 2 byte message
    assert (buffer [2] == 0);       //  Flags = 0
    assert (buffer [3] == 0);       //  Size = 0

    //  Then we have a 5-byte message "Hello"
    assert (buffer [4] == 0);       //  Flags = 0
    assert (buffer [5] == 5);       //  Size = 5
    assert (memcmp (buffer + 6, "Hello", 5) == 0);

    //  Send "World" back to DEALER
    rc = zmq_msg_send (&identity, router, ZMQ_SNDMORE);
    assert (rc > 0);
    byte world [] = { 0, 5, 'W', 'o', 'r', 'l', 'd' };
    rc = zmq_send (router, world, sizeof (world), 0);
    assert (rc == sizeof (world));

    //  Expect response on DEALER socket
    rc = zmq_recv (dealer, buffer, 255, 0);
    assert (rc == 5);
    assert (memcmp (buffer, "World", 5) == 0);

    rc = zmq_close (dealer);
    assert (rc == 0);

    rc = zmq_close (router);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    return 0;
}
