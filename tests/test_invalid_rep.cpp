/*
    Copyright (c) 2010-2011 250bpm s.r.o.
    Copyright (c) 2011 VMware, Inc.
    Copyright (c) 2010-2011 Other contributors as noted in the AUTHORS file

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
#include <stdio.h>

#undef NDEBUG
#include <assert.h>

int main (void)
{
    fprintf (stderr, "test_invalid_rep running...\n");

    //  Create REQ/ROUTER wiring.
    void *ctx = zmq_init (1);
    assert (ctx);
    void *router_socket = zmq_socket (ctx, ZMQ_ROUTER);
    assert (router_socket);
    void *req_socket = zmq_socket (ctx, ZMQ_REQ);
    assert (req_socket);
    int linger = 0;
    int rc = zmq_setsockopt (router_socket, ZMQ_LINGER, &linger, sizeof (int));
    assert (rc == 0);
    rc = zmq_setsockopt (req_socket, ZMQ_LINGER, &linger, sizeof (int));
    assert (rc == 0);
    rc = zmq_bind (router_socket, "inproc://hi");
    assert (rc == 0);
    rc = zmq_connect (req_socket, "inproc://hi");
    assert (rc == 0);

    //  Initial request.
    rc = zmq_send (req_socket, "r", 1, 0);
    assert (rc == 1);

    //  Receive the request.
    char addr [32];
    int addr_size;
    char bottom [1];
    char body [1];
    addr_size = zmq_recv (router_socket, addr, sizeof (addr), 0);
    assert (addr_size >= 0);
    rc = zmq_recv (router_socket, bottom, sizeof (bottom), 0);
    assert (rc == 0);
    rc = zmq_recv (router_socket, body, sizeof (body), 0);
    assert (rc == 1);

    //  Send invalid reply.
    rc = zmq_send (router_socket, addr, addr_size, 0);
    assert (rc == addr_size);

    //  Send valid reply.
    rc = zmq_send (router_socket, addr, addr_size, ZMQ_SNDMORE);
    assert (rc == addr_size);
    rc = zmq_send (router_socket, bottom, 0, ZMQ_SNDMORE);
    assert (rc == 0);
    rc = zmq_send (router_socket, "b", 1, 0);
    assert (rc == 1);

    //  Check whether we've got the valid reply.
    rc = zmq_recv (req_socket, body, sizeof (body), 0);
    assert (rc == 1);
	assert (body [0] == 'b');

    //  Tear down the wiring.
    rc = zmq_close (router_socket);
    assert (rc == 0);
    rc = zmq_close (req_socket);
    assert (rc == 0);
    rc = zmq_term (ctx);
    assert (rc == 0);

    return 0;
}

