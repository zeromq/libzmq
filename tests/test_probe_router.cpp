/*
    Copyright (c) 2007-2014 Contributors as noted in the AUTHORS file

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

#include "testutil.hpp"

int main (void)
{
    setup_test_environment();
    void *ctx = zmq_ctx_new ();
    assert (ctx);
    
    //  Create server and bind to endpoint
    void *server = zmq_socket (ctx, ZMQ_ROUTER);
    assert (server);
    int rc = zmq_bind (server, "tcp://127.0.0.1:5560");
    assert (rc == 0);

    //  Create client and connect to server, doing a probe
    void *client = zmq_socket (ctx, ZMQ_ROUTER);
    assert (client);
    rc = zmq_setsockopt (client, ZMQ_IDENTITY, "X", 1);
    assert (rc == 0);
    int probe = 1;
    rc = zmq_setsockopt (client, ZMQ_PROBE_ROUTER, &probe, sizeof (probe));
    assert (rc == 0);
    rc = zmq_connect (client, "tcp://localhost:5560");
    assert (rc == 0);

    //  We expect an identity=X + empty message from client
    unsigned char buffer [255];
    rc = zmq_recv (server, buffer, 255, 0);
    assert (rc == 1);
    assert (buffer [0] ==  'X');
    rc = zmq_recv (server, buffer, 255, 0);
    assert (rc == 0);

    //  Send a message to client now
    rc = zmq_send (server, "X", 1, ZMQ_SNDMORE);
    assert (rc == 1);
    rc = zmq_send (server, "Hello", 5, 0);
    assert (rc == 5);
    
    rc = zmq_recv (client, buffer, 255, 0);
    assert (rc == 5);
    
    rc = zmq_close (server);
    assert (rc == 0);

    rc = zmq_close (client);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    return 0 ;
}
