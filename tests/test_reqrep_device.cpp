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

#include <assert.h>
#include <string.h>
#include <stdio.h>

#include "../include/zmq.h"

int main (int argc, char *argv [])
{
    fprintf (stderr, "test_reqrep_device running...\n");

    void *ctx = zmq_init (1);
    assert (ctx);

    //  Create a req/rep device.
    void *xreq = zmq_socket (ctx, ZMQ_XREQ);
    assert (xreq);
    int rc = zmq_bind (xreq, "tcp://127.0.0.1:5560");
    assert (rc == 0);
    void *xrep = zmq_socket (ctx, ZMQ_XREP);
    assert (xrep);
    rc = zmq_bind (xrep, "tcp://127.0.0.1:5561");
    assert (rc == 0);

    //  Create a worker.
    void *rep = zmq_socket (ctx, ZMQ_REP);
    assert (rep);
    rc = zmq_connect (rep, "tcp://127.0.0.1:5560");
    assert (rc == 0);

    //  Create a client.
    void *req = zmq_socket (ctx, ZMQ_REQ);
    assert (req);
    rc = zmq_connect (req, "tcp://127.0.0.1:5561");
    assert (rc == 0);

    //  Send a request.
    rc = zmq_send (req, "ABC", 3, ZMQ_SNDMORE);
    assert (rc == 3);
    rc = zmq_send (req, "DEF", 3, 0);
    assert (rc == 3);

    //  Pass the request through the device.
    for (int i = 0; i != 4; i++) {
        zmq_msg_t msg;
        rc = zmq_msg_init (&msg);
        assert (rc == 0);
        rc = zmq_recvmsg (xrep, &msg, 0);
        assert (rc >= 0);
        int rcvmore;
        size_t sz = sizeof (rcvmore);
        rc = zmq_getsockopt (xrep, ZMQ_RCVMORE, &rcvmore, &sz);
        assert (rc == 0);
        rc = zmq_sendmsg (xreq, &msg, rcvmore ? ZMQ_SNDMORE : 0);
        assert (rc >= 0);
    }

    //  Receive the request.
    char buff [3];
    rc = zmq_recv (rep, buff, 3, 0);
    assert (rc == 3);
    assert (memcmp (buff, "ABC", 3) == 0);
    int rcvmore;
    size_t sz = sizeof (rcvmore);
    rc = zmq_getsockopt (rep, ZMQ_RCVMORE, &rcvmore, &sz);
    assert (rc == 0);
    assert (rcvmore);
    rc = zmq_recv (rep, buff, 3, 0);
    assert (rc == 3);
    assert (memcmp (buff, "DEF", 3) == 0);
    rc = zmq_getsockopt (rep, ZMQ_RCVMORE, &rcvmore, &sz);
    assert (rc == 0);
    assert (!rcvmore);

    //  Send the reply.
    rc = zmq_send (rep, "GHI", 3, ZMQ_SNDMORE);
    assert (rc == 3);
    rc = zmq_send (rep, "JKL", 3, 0);
    assert (rc == 3);

    //  Pass the reply through the device.
    for (int i = 0; i != 4; i++) {
        zmq_msg_t msg;
        rc = zmq_msg_init (&msg);
        assert (rc == 0);
        rc = zmq_recvmsg (xreq, &msg, 0);
        assert (rc >= 0);
        int rcvmore;
        rc = zmq_getsockopt (xreq, ZMQ_RCVMORE, &rcvmore, &sz);
        assert (rc == 0);
        rc = zmq_sendmsg (xrep, &msg, rcvmore ? ZMQ_SNDMORE : 0);
        assert (rc >= 0);
    }

    //  Receive the reply.
    rc = zmq_recv (req, buff, 3, 0);
    assert (rc == 3);
    assert (memcmp (buff, "GHI", 3) == 0);
    rc = zmq_getsockopt (req, ZMQ_RCVMORE, &rcvmore, &sz);
    assert (rc == 0);
    assert (rcvmore);
    rc = zmq_recv (req, buff, 3, 0);
    assert (rc == 3);
    assert (memcmp (buff, "JKL", 3) == 0);
    rc = zmq_getsockopt (req, ZMQ_RCVMORE, &rcvmore, &sz);
    assert (rc == 0);
    assert (!rcvmore);

    //  Clean up.
    rc = zmq_close (req);
    assert (rc == 0);
    rc = zmq_close (rep);
    assert (rc == 0);
    rc = zmq_close (xrep);
    assert (rc == 0);
    rc = zmq_close (xreq);
    assert (rc == 0);
    rc = zmq_term (ctx);
    assert (rc == 0);

    return 0 ;
}
