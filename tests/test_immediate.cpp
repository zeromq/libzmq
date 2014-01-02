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
    int val;
    int rc;
    char buffer[16];
    // TEST 1. 
    // First we're going to attempt to send messages to two
    // pipes, one connected, the other not. We should see
    // the PUSH load balancing to both pipes, and hence half
    // of the messages getting queued, as connect() creates a
    // pipe immediately. 
    
    void *context = zmq_ctx_new();
    assert (context);
    void *to = zmq_socket(context, ZMQ_PULL);
    assert (to);

    // Bind the one valid receiver
    val = 0;
    rc = zmq_setsockopt(to, ZMQ_LINGER, &val, sizeof(val));
    assert (rc == 0);
    rc = zmq_bind (to, "tcp://127.0.0.1:6555");
    assert (rc == 0);

    // Create a socket pushing to two endpoints - only 1 message should arrive.
    void *from = zmq_socket (context, ZMQ_PUSH);
    assert(from);

    val = 0;
    zmq_setsockopt (from, ZMQ_LINGER, &val, sizeof (val));
    // This pipe will not connect
    rc = zmq_connect (from, "tcp://localhost:5556");
    assert (rc == 0);
    // This pipe will 
    rc = zmq_connect (from, "tcp://localhost:6555");
    assert (rc == 0);

    // We send 10 messages, 5 should just get stuck in the queue
    // for the not-yet-connected pipe
    for (int i = 0; i < 10; ++i) {
        rc = zmq_send (from, "Hello", 5, 0);
        assert (rc == 5);
    }

    // We now consume from the connected pipe
    // - we should see just 5
    int timeout = 100;
    rc = zmq_setsockopt (to, ZMQ_RCVTIMEO, &timeout, sizeof (int));
    assert (rc == 0);

    int seen = 0;
    while (true) {
        rc = zmq_recv (to, &buffer, sizeof (buffer), 0);
        if (rc == -1)
            break;          //  Break when we didn't get a message
        seen++;
    }
    assert (seen == 5);

    rc = zmq_close (from);
    assert (rc == 0);

    rc = zmq_close (to);
    assert (rc == 0);

    rc = zmq_ctx_term (context);
    assert (rc == 0);

    // TEST 2
    // This time we will do the same thing, connect two pipes, 
    // one of which will succeed in connecting to a bound 
    // receiver, the other of which will fail. However, we will 
    // also set the delay attach on connect flag, which should 
    // cause the pipe attachment to be delayed until the connection
    // succeeds. 
    context = zmq_ctx_new();

    // Bind the valid socket
    to = zmq_socket (context, ZMQ_PULL);
    assert (to);
    rc = zmq_bind (to, "tcp://127.0.0.1:5560");
    assert (rc == 0);

    val = 0;
    rc = zmq_setsockopt (to, ZMQ_LINGER, &val, sizeof(val));
    assert (rc == 0);

    // Create a socket pushing to two endpoints - all messages should arrive.
    from = zmq_socket (context, ZMQ_PUSH);
    assert (from);

    val = 0;
    rc = zmq_setsockopt (from, ZMQ_LINGER, &val, sizeof(val));
    assert (rc == 0);

    // Set the key flag
    val = 1;
    rc = zmq_setsockopt (from, ZMQ_IMMEDIATE, &val, sizeof(val));
    assert (rc == 0);

    // Connect to the invalid socket
    rc = zmq_connect (from, "tcp://localhost:5561");
    assert (rc == 0);
    // Connect to the valid socket
    rc = zmq_connect (from, "tcp://localhost:5560");
    assert (rc == 0);

    // Send 10 messages, all should be routed to the connected pipe
    for (int i = 0; i < 10; ++i) {
        rc = zmq_send (from, "Hello", 5, 0);
        assert (rc == 5);
    }
    rc = zmq_setsockopt (to, ZMQ_RCVTIMEO, &timeout, sizeof (int));
    assert (rc == 0);
    
    seen = 0;
    while (true) {
        rc = zmq_recv (to, &buffer, sizeof (buffer), 0);
        if (rc == -1)
            break;          //  Break when we didn't get a message
        seen++;
    }
    assert (seen == 10);

    rc = zmq_close (from);
    assert (rc == 0);

    rc = zmq_close (to);
    assert (rc == 0);
    
    rc = zmq_ctx_term (context);
    assert (rc == 0);

    // TEST 3
    // This time we want to validate that the same blocking behaviour
    // occurs with an existing connection that is broken. We will send
    // messages to a connected pipe, disconnect and verify the messages
    // block. Then we reconnect and verify messages flow again.
    context = zmq_ctx_new ();

    void *backend = zmq_socket (context, ZMQ_DEALER);
    assert (backend);
    void *frontend = zmq_socket (context, ZMQ_DEALER);
    assert (frontend);
    int zero = 0;
    rc = zmq_setsockopt (backend, ZMQ_LINGER, &zero, sizeof (zero));
    assert (rc == 0);
    rc = zmq_setsockopt (frontend, ZMQ_LINGER, &zero, sizeof (zero));
    assert (rc == 0);

    //  Frontend connects to backend using IMMEDIATE
    int on = 1;
    rc = zmq_setsockopt (frontend, ZMQ_IMMEDIATE, &on, sizeof (on));
    assert (rc == 0);
    rc = zmq_bind (backend, "tcp://127.0.0.1:5560");
    assert (rc == 0);
    rc = zmq_connect (frontend, "tcp://localhost:5560");
    assert (rc == 0);

    //  Ping backend to frontend so we know when the connection is up
    rc = zmq_send (backend, "Hello", 5, 0);
    assert (rc == 5);
    rc = zmq_recv (frontend, buffer, 255, 0);
    assert (rc == 5);
    
    // Send message from frontend to backend
    rc = zmq_send (frontend, "Hello", 5, ZMQ_DONTWAIT);
    assert (rc == 5);
    
    rc = zmq_close (backend);
    assert (rc == 0);

    //  Give time to process disconnect
    msleep (SETTLE_TIME * 10);
    
    // Send a message, should fail
    rc = zmq_send (frontend, "Hello", 5, ZMQ_DONTWAIT);
    assert (rc == -1);

    //  Recreate backend socket
    backend = zmq_socket (context, ZMQ_DEALER);
    assert (backend);
    rc = zmq_setsockopt (backend, ZMQ_LINGER, &zero, sizeof (zero));
    assert (rc == 0);
    rc = zmq_bind (backend, "tcp://127.0.0.1:5560");
    assert (rc == 0);

    //  Ping backend to frontend so we know when the connection is up
    rc = zmq_send (backend, "Hello", 5, 0);
    assert (rc == 5);
    rc = zmq_recv (frontend, buffer, 255, 0);
    assert (rc == 5);

    // After the reconnect, should succeed
    rc = zmq_send (frontend, "Hello", 5, ZMQ_DONTWAIT);
    assert (rc == 5);
    
    rc = zmq_close (backend);
    assert (rc == 0);
    
    rc = zmq_close (frontend);
    assert (rc == 0);

    rc = zmq_ctx_term (context);
    assert (rc == 0);
}
