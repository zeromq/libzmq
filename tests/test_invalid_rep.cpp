/*
    Copyright (c) 2007-2011 iMatix Corporation
    Copyright (c) 2007-2011 Other contributors as noted in the AUTHORS file

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
#include <assert.h>
//#include <stdio.h>

int main (int argc, char *argv [])
{
    //  Create REQ/XREP wiring.
    void *ctx = zmq_init (1);
    assert (ctx);
    void *xrep_socket = zmq_socket (ctx, ZMQ_XREP);
    assert (xrep_socket);
    void *req_socket = zmq_socket (ctx, ZMQ_REQ);
    assert (req_socket);
    int linger = 0;
    int rc = zmq_setsockopt (xrep_socket, ZMQ_LINGER, &linger, sizeof (int));
    assert (rc == 0);
    rc = zmq_setsockopt (req_socket, ZMQ_LINGER, &linger, sizeof (int));
    assert (rc == 0);
    rc = zmq_bind (xrep_socket, "inproc://hi");
    assert (rc == 0);
    rc = zmq_connect (req_socket, "inproc://hi");
    assert (rc == 0);

    //  Initial request.
    rc = zmq_send (req_socket, "r", 1, 0);
    assert (rc == 1);

    //  Receive the request.
    char addr [4];
    char seqn [4];
    char body [1];
    rc = zmq_recv (xrep_socket, addr, sizeof (addr), 0);
    assert (rc == 4);
    rc = zmq_recv (xrep_socket, seqn, sizeof (seqn), 0);
    assert (rc == 4);
    rc = zmq_recv (xrep_socket, body, sizeof (body), 0);
    assert (rc == 1);

    //  Send invalid reply (addr not label).
    rc = zmq_send (xrep_socket, addr, 4, 0);
    assert (rc == 4);

    rc = zmq_recv (req_socket, body, sizeof (body), ZMQ_DONTWAIT);
    assert (rc == -1);

    //  Send invalid reply (ID not label).
    rc = zmq_send (xrep_socket, addr, 4, ZMQ_SNDLABEL);
    assert (rc == 4);
    rc = zmq_send (xrep_socket, seqn, 4, 0);             // right ID, not label!
    assert (rc == 4);

    rc = zmq_recv (req_socket, body, sizeof (body), ZMQ_DONTWAIT);
    assert (rc == -1);

    // Send invalid reply (bad ID labels, followed by good label, invalid data),
    // ensuring that we always discard entire message (and not leak), if ID
    // is found to be invalid.
    rc = zmq_send (xrep_socket, addr, 4, ZMQ_SNDLABEL);  // right address
    assert (rc == 4);
    rc = zmq_send (xrep_socket, seqn, 3, ZMQ_SNDLABEL);  // wrong ID size
    assert (rc == 3);
    rc = zmq_send (xrep_socket, seqn, 3, ZMQ_SNDLABEL);  // ''
    assert (rc == 3);
    rc = zmq_send (xrep_socket, seqn, 3, ZMQ_SNDLABEL);  // ''
    assert (rc == 3);
    rc = zmq_send (xrep_socket, seqn, 3, ZMQ_SNDLABEL);  // ''
    assert (rc == 3);
    rc = zmq_send (xrep_socket, seqn, 3, ZMQ_SNDLABEL);  // ''
    assert (rc == 3);
    rc = zmq_send (xrep_socket, seqn, 3, ZMQ_SNDLABEL);  // ''
    assert (rc == 3);
    rc = zmq_send (xrep_socket, seqn, 4, ZMQ_SNDLABEL);  // right ID!
    assert (rc == 4);
    rc = zmq_send (xrep_socket, "v", 1, 0);              // but bad data
    assert (rc == 1);

    rc = zmq_recv (req_socket, body, sizeof (body), ZMQ_DONTWAIT);
    assert (rc == -1);

    // Send invalid reply (bad ID label, followed by good label, invalid data).
    rc = zmq_send (xrep_socket, addr, 4, ZMQ_SNDLABEL);  // right address
    assert (rc == 4);
    rc = zmq_send (xrep_socket, addr, 4, ZMQ_SNDLABEL);  // wrong ID value
    assert (rc == 4);
    rc = zmq_send (xrep_socket, seqn, 4, ZMQ_SNDLABEL);  // right ID!
    assert (rc == 4);
    rc = zmq_send (xrep_socket, seqn, 4, ZMQ_SNDLABEL);  // ''
    assert (rc == 4);
    rc = zmq_send (xrep_socket, "w", 1, 0);              // but bad data
    assert (rc == 1);

    rc = zmq_recv (req_socket, body, sizeof (body), ZMQ_DONTWAIT);
    assert (rc == -1);

    // Send invalid reply (not label, followed by good label, invalid data).
    rc = zmq_send (xrep_socket, addr, 4, ZMQ_SNDLABEL);  // right address
    assert (rc == 4);
    rc = zmq_send (xrep_socket, seqn, 4, ZMQ_SNDMORE);   // right ID, but not a label
    assert (rc == 4);
    rc = zmq_send (xrep_socket, addr, 4, ZMQ_SNDLABEL);  // right address
    assert (rc == 4);
    rc = zmq_send (xrep_socket, seqn, 4, ZMQ_SNDLABEL);  // right ID!
    assert (rc == 4);
    rc = zmq_send (xrep_socket, "x", 1, 0);              // but bad data
    assert (rc == 1);

    rc = zmq_recv (req_socket, body, sizeof (body), ZMQ_DONTWAIT);
    assert (rc == -1);


    // Send valid reply.
    rc = zmq_send (xrep_socket, addr, 4, ZMQ_SNDLABEL);
    assert (rc == 4);
    rc = zmq_send (xrep_socket, seqn, 4, ZMQ_SNDLABEL);
    assert (rc == 4);
    rc = zmq_send (xrep_socket, "b", 1, 0);
    assert (rc == 1);

    //  Check whether we've got only the (final) valid reply (and no more).
    rc = zmq_recv (req_socket, body, sizeof (body), 0);
    assert (rc == 1);
    //printf( "body: %c\n", *body );
    assert (body [0] == 'b');

    rc = zmq_recv (req_socket, body, sizeof (body), ZMQ_DONTWAIT);
    assert (rc == -1);


    //  Tear down the wiring.
    rc = zmq_close (xrep_socket);
    assert (rc == 0);
    rc = zmq_close (req_socket);
    assert (rc == 0);
    rc = zmq_term (ctx);
    assert (rc == 0);

    return 0;
}

