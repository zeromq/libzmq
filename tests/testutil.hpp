/*
    Copyright (c) 2007-2013 Contributors as noted in the AUTHORS file

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

#ifndef __TESTUTIL_HPP_INCLUDED__
#define __TESTUTIL_HPP_INCLUDED__

#include "../include/zmq.h"
#include <string.h>
#undef NDEBUG
#include <assert.h>

//  Bounce a message from client to server and back
//  For REQ/REP or DEALER/DEALER pairs only

static void
bounce (void *server, void *client)
{
    const char *content = "12345678ABCDEFGH12345678abcdefgh";

    //  Send message from client to server
    int rc = zmq_send (client, content, 32, ZMQ_SNDMORE);
    assert (rc == 32);
    rc = zmq_send (client, content, 32, 0);
    assert (rc == 32);

    //  Receive message at server side
    char buffer [32];
    rc = zmq_recv (server, buffer, 32, 0);
    assert (rc == 32);
    int rcvmore;
    size_t sz = sizeof (rcvmore);
    rc = zmq_getsockopt (server, ZMQ_RCVMORE, &rcvmore, &sz);
    assert (rc == 0);
    assert (rcvmore);
    rc = zmq_recv (server, buffer, 32, 0);
    assert (rc == 32);
    rc = zmq_getsockopt (server, ZMQ_RCVMORE, &rcvmore, &sz);
    assert (rc == 0);
    assert (!rcvmore);
    
    //  Send two parts back to client
    rc = zmq_send (server, buffer, 32, ZMQ_SNDMORE);
    assert (rc == 32);
    rc = zmq_send (server, buffer, 32, 0);
    assert (rc == 32);

    //  Receive the two parts at the client side
    rc = zmq_recv (client, buffer, 32, 0);
    assert (rc == 32);
    rc = zmq_getsockopt (client, ZMQ_RCVMORE, &rcvmore, &sz);
    assert (rc == 0);
    assert (rcvmore);
    rc = zmq_recv (client, buffer, 32, 0);
    assert (rc == 32);
    rc = zmq_getsockopt (client, ZMQ_RCVMORE, &rcvmore, &sz);
    assert (rc == 0);
    assert (!rcvmore);

    //  Check that message is still the same
    assert (memcmp (buffer, content, 32) == 0);
}

#endif
