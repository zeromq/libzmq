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

#include <assert.h>

#include "../include/zmq.h"
#include "../include/zmq_utils.h"

int main (int argc, char *argv [])
{
    void *ctx = zmq_init (1);
    assert (ctx);

    //  Check whether requests are discarded because of disconnected requester.

    //  Create a server.
    void *xrep = zmq_socket (ctx, ZMQ_XREP);
    assert (xrep);
    int rc = zmq_bind (xrep, "tcp://127.0.0.1:5560");
    assert (rc == 0);

    //  Create a client.
    void *xreq = zmq_socket (ctx, ZMQ_XREQ);
    assert (xreq);
    rc = zmq_connect (xreq, "tcp://127.0.0.1:5560");
    assert (rc == 0);

    //  Send requests.
    rc = zmq_send (xreq, "ABC", 3, 0);
    assert (rc == 3);
    rc = zmq_send (xreq, "DEF", 3, 0);
    assert (rc == 3);

    //  Disconnect client.
    rc = zmq_close (xreq);
    assert (rc == 0);

    //  Wait a while for disconnect to happen.
    zmq_sleep (1);

    //  Try to receive a request -- it should have been discarded.
    char buff [3];
    rc = zmq_recv (xrep, buff, 3, ZMQ_DONTWAIT);
    assert (rc < 0);
    assert (errno == EAGAIN);

    //  Clean up.
    rc = zmq_close (xrep);
    assert (rc == 0);

    //  New test. Check whether reply is dropped because of HWM overflow.

    int one = 1;
    xreq = zmq_socket (ctx, ZMQ_XREQ);
    assert (xreq);
    rc = zmq_setsockopt (xreq, ZMQ_RCVHWM, &one, sizeof(one));
    assert (rc == 0);
    rc = zmq_bind (xreq, "inproc://a");
    assert (rc == 0);

    void *rep = zmq_socket (ctx, ZMQ_REP);
    assert (rep);
    rc = zmq_setsockopt (rep, ZMQ_SNDHWM, &one, sizeof(one));
    assert (rc == 0);
    rc = zmq_connect (rep, "inproc://a");
    assert (rc == 0);

    //  Send request 1
    rc = zmq_send (xreq, buff, 1, 0);
    assert (rc == 1);

    //  Send request 2
    rc = zmq_send (xreq, buff, 1, 0);
    assert (rc == 1);

    //  Receive request 1
    rc = zmq_recv (rep, buff, 1, 0);
    assert (rc == 1);

    //  Send request 3
    rc = zmq_send (xreq, buff, 1, 0);
    assert (rc == 1);

    //  Send reply 1
    rc = zmq_send (rep, buff, 1, 0);
    assert (rc == 1);

    //  Receive request 2
    rc = zmq_recv (rep, buff, 1, 0);
    assert (rc == 1);

    //  Send reply 2
    rc = zmq_send (rep, buff, 1, 0);
    assert (rc == 1);

    //  Receive request 3
    rc = zmq_recv (rep, buff, 1, 0);
    assert (rc == 1);

    //  Send reply 3
    rc = zmq_send (rep, buff, 1, 0);
    assert (rc == 1);

    //  Receive reply 1
    rc = zmq_recv (xreq, buff, 1, 0);
    assert (rc == 1);

    //  Receive reply 2
    rc = zmq_recv (xreq, buff, 1, 0);
    assert (rc == 1);

    //  Try to receive reply 3, it should have been dropped.
    rc = zmq_recv (xreq, buff, 1, ZMQ_DONTWAIT);
    assert (rc == -1 && errno == EAGAIN);

    //  Clean up.
    rc = zmq_close (xreq);
    assert (rc == 0);
    rc = zmq_close (rep);
    assert (rc == 0);

    rc = zmq_term (ctx);
    assert (rc == 0);

    return 0 ;
}
