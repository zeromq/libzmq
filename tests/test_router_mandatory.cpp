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

#include "testutil.hpp"

int main (void)
{
    setup_test_environment();
    void *ctx = zmq_ctx_new ();
    assert (ctx);
    void *router = zmq_socket (ctx, ZMQ_ROUTER);
    assert (router);

    int rc = zmq_bind (router, "tcp://127.0.0.1:5560");
    assert (rc == 0);

    //  Send a message to an unknown peer with the default setting
    //  This will not report any error
    rc = zmq_send (router, "UNKNOWN", 7, ZMQ_SNDMORE);
    assert (rc == 7);
    rc = zmq_send (router, "DATA", 4, 0);
    assert (rc == 4);

    //  Send a message to an unknown peer with mandatory routing
    //  This will fail
    int mandatory = 1;
    rc = zmq_setsockopt (router, ZMQ_ROUTER_MANDATORY, &mandatory, sizeof (mandatory));
    assert (rc == 0);
    rc = zmq_send (router, "UNKNOWN", 7, ZMQ_SNDMORE);
    assert (rc == -1 && errno == EHOSTUNREACH);

    //  Create dealer called "X" and connect it to our router
    void *dealer = zmq_socket (ctx, ZMQ_DEALER);
    assert (dealer);
    rc = zmq_setsockopt (dealer, ZMQ_IDENTITY, "X", 1);
    assert (rc == 0);
    rc = zmq_connect (dealer, "tcp://127.0.0.1:5560");
    assert (rc == 0);

    //  Get message from dealer to know when connection is ready
    char buffer [255];
    rc = zmq_send (dealer, "Hello", 5, 0);
    assert (rc == 5);
    rc = zmq_recv (router, buffer, 255, 0);
    assert (rc == 1);
    assert (buffer [0] ==  'X');

    //  Send a message to connected dealer now
    //  It should work
    rc = zmq_send (router, "X", 1, ZMQ_SNDMORE);
    assert (rc == 1);
    rc = zmq_send (router, "Hello", 5, 0);
    assert (rc == 5);
    
    rc = zmq_close (router);
    assert (rc == 0);

    rc = zmq_close (dealer);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    return 0 ;
}
