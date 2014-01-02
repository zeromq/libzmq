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
    void *router = zmq_socket (ctx, ZMQ_ROUTER);
    assert (router);

    int rc = zmq_bind (router, "tcp://127.0.0.1:5560");
    assert (rc == 0);

    // Enable the handover flag
    int handover = 1;
    rc = zmq_setsockopt (router, ZMQ_ROUTER_HANDOVER, &handover, sizeof (handover));
    assert (rc == 0);

    //  Create dealer called "X" and connect it to our router
    void *dealer_one = zmq_socket (ctx, ZMQ_DEALER);
    assert (dealer_one);
    rc = zmq_setsockopt (dealer_one, ZMQ_IDENTITY, "X", 1);
    assert (rc == 0);
    rc = zmq_connect (dealer_one, "tcp://127.0.0.1:5560");
    assert (rc == 0);
    
    //  Get message from dealer to know when connection is ready
    char buffer [255];
    rc = zmq_send (dealer_one, "Hello", 5, 0);
    assert (rc == 5);
    rc = zmq_recv (router, buffer, 255, 0);
    assert (rc == 1);
    assert (buffer [0] ==  'X');
    rc = zmq_recv (router, buffer, 255, 0);
    assert (rc == 5);

    // Now create a second dealer that uses the same identity
    void *dealer_two = zmq_socket (ctx, ZMQ_DEALER);
    assert (dealer_two);
    rc = zmq_setsockopt (dealer_two, ZMQ_IDENTITY, "X", 1);
    assert (rc == 0);
    rc = zmq_connect (dealer_two, "tcp://127.0.0.1:5560");
    assert (rc == 0);

    //  Get message from dealer to know when connection is ready
    rc = zmq_send (dealer_two, "Hello", 5, 0);
    assert (rc == 5);
    rc = zmq_recv (router, buffer, 255, 0);
    assert (rc == 1);
    assert (buffer [0] ==  'X');
    rc = zmq_recv (router, buffer, 255, 0);
    assert (rc == 5);

    //  Send a message to 'X' identity. This should be delivered 
    //  to the second dealer, instead of the first beccause of the handover.
    rc = zmq_send (router, "X", 1, ZMQ_SNDMORE);
    assert (rc == 1);
    rc = zmq_send (router, "Hello", 5, 0);
    assert (rc == 5);

    //  Ensure that the first dealer doesn't receive the message
    //  but the second one does 
    rc = zmq_recv (dealer_one, buffer, 255, ZMQ_NOBLOCK);
    assert (rc == -1);

    rc = zmq_recv (dealer_two, buffer, 255, 0);
    assert (rc == 5);
 
    rc = zmq_close (router);
    assert (rc == 0);

    rc = zmq_close (dealer_one);
    assert (rc == 0);

    rc = zmq_close (dealer_two);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    return 0 ;
}
