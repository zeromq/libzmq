/*
Copyright (c) 2012 Ian Barber
Copyright (c) 2012 Other contributors as noted in the AUTHORS file

This file is part of 0MQ.

0MQ is free software; you can redistribute it and/or modify it under
the terms of the GNU Lesser General Public License as published by
the Free Software Foundation; either version 3 of the License, or
(at your option) any later version.

0MQ is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include "../include/zmq.h"
#include "../include/zmq_utils.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <string>

#undef NDEBUG
#include <assert.h>

int main (void)
{
    fprintf (stderr, "test_connect_delay running...\n");
    int val;
    int rc;
    char buffer[16];
    int seen = 0;

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
    rc = zmq_bind(to, "tcp://*:5555");
    assert (rc == 0);

    // Create a socket pushing to two endpoints - only 1 message should arrive.
    void *from = zmq_socket (context, ZMQ_PUSH);
    assert(from);

    val = 0;
    zmq_setsockopt (from, ZMQ_LINGER, &val, sizeof(val));
    // This pipe will not connect
    rc = zmq_connect (from, "tcp://localhost:5556");
    assert (rc == 0);
    // This pipe will 
    rc = zmq_connect (from, "tcp://localhost:5555");
    assert (rc == 0);

    // We send 10 messages, 5 should just get stuck in the queue
    // for the not-yet-connected pipe
    for (int i = 0; i < 10; ++i)
    {
        std::string message("message ");
        message += ('0' + i);
        rc = zmq_send (from, message.data(), message.size(), 0);
        assert(rc >= 0);
    }

    // Sleep to allow the messages to be delivered
    zmq_sleep (1);
    
    // We now consume from the connected pipe
    // - we should see just 5
    seen = 0;
    for (int i = 0; i < 10; ++i)
    {
        memset (&buffer, 0, sizeof(buffer));
        rc = zmq_recv (to, &buffer, sizeof(buffer), ZMQ_DONTWAIT);
        if( rc == -1)
            break;
        seen++;
    }
    assert (seen == 5);

    rc = zmq_close (from);
    assert (rc == 0);

    rc = zmq_close (to);
    assert (rc == 0);

    rc = zmq_ctx_destroy(context);
    assert (rc == 0);

    // TEST 2
    // This time we will do the same thing, connect two pipes, 
    // one of which will succeed in connecting to a bound 
    // receiver, the other of which will fail. However, we will 
    // also set the delay attach on connect flag, which should 
    // cause the pipe attachment to be delayed until the connection
    // succeeds. 
    context = zmq_ctx_new();
    fprintf (stderr, " Rerunning with DELAY_ATTACH_ON_CONNECT\n");

    // Bind the valid socket
    to = zmq_socket (context, ZMQ_PULL);
    assert (to);
    rc = zmq_bind (to, "tcp://*:5560");
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
    rc = zmq_setsockopt (from, ZMQ_DELAY_ATTACH_ON_CONNECT, &val, sizeof(val));
    assert (rc == 0);

    // Connect to the invalid socket
    rc = zmq_connect (from, "tcp://localhost:5561");
    assert (rc == 0);
    // Connect to the valid socket
    rc = zmq_connect (from, "tcp://localhost:5560");
    assert (rc == 0);

    // Send 10 messages, all should be routed to the connected pipe
    for (int i = 0; i < 10; ++i)
    {
        std::string message("message ");
        message += ('0' + i);
        rc = zmq_send (from, message.data(), message.size(), 0);
        assert (rc >= 0);
    }

    // Sleep to allow the messages to be delivered
    zmq_sleep (1);

    // Send 10 messages, all should arrive. 
    seen = 0;
    for (int i = 0; i < 10; ++i)
    {
        memset(&buffer, 0, sizeof(buffer));
        rc = zmq_recv (to, &buffer, sizeof(buffer), ZMQ_DONTWAIT);
        // If there is a failed delivery, assert!
        assert (rc != -1);
    }

    rc = zmq_close (from);
    assert (rc == 0);

    rc = zmq_close (to);
    assert (rc == 0);
    
    rc = zmq_ctx_destroy(context);
    assert (rc == 0);

    // TEST 3
    // This time we want to validate that the same blocking behaviour
    // occurs with an existing connection that is broken. We will send
    // messaages to a connected pipe, disconnect and verify the messages
    // block. Then we reconnect and verify messages flow again.
    context = zmq_ctx_new();
    void *context2 = zmq_ctx_new();
    fprintf (stderr, " Running DELAY_ATTACH_ON_CONNECT with disconnect\n");

    to = zmq_socket (context2, ZMQ_PULL);
    assert (to);
    rc = zmq_bind (to, "tcp://*:5560");
    assert (rc == 0);

    val = 0;
    rc = zmq_setsockopt (to, ZMQ_LINGER, &val, sizeof(val));
    assert (rc == 0);

    // Create a socket pushing 
    from = zmq_socket (context, ZMQ_PUSH);
    assert (from);

    val = 0;
    rc = zmq_setsockopt (from, ZMQ_LINGER, &val, sizeof(val));
    assert (rc == 0);
    val = 1;
    rc = zmq_setsockopt (from, ZMQ_DELAY_ATTACH_ON_CONNECT, &val, sizeof(val));
    assert (rc == 0);

    // Connect to the valid socket socket
    rc = zmq_connect (from, "tcp://localhost:5560");
    assert (rc == 0);
    
    // Allow connections to stabilise
    zmq_sleep(1);
    
    // Send a message, should succeed
    std::string message("message ");
    rc = zmq_send (from, message.data(), message.size(), 0);
    assert (rc >= 0);
    
    rc = zmq_close (to);
    assert (rc == 0);
    
    rc = zmq_ctx_destroy(context2);
    assert (rc == 0);
    
    // Give time to process disconnect
    zmq_sleep(1);
    
    // Send a message, should fail
    rc = zmq_send (from, message.data(), message.size(), ZMQ_DONTWAIT);
    assert (rc == -1);
    
    context2 = zmq_ctx_new();
    to = zmq_socket (context2, ZMQ_PULL);
    assert (to);
    rc = zmq_bind (to, "tcp://*:5560");
    assert (rc == 0);

    val = 0;
    rc = zmq_setsockopt (to, ZMQ_LINGER, &val, sizeof(val));
    assert (rc == 0);
    
    // Allow connections to stabilise
    zmq_sleep(1);
    
    // After the reconnect, should succeed
    rc = zmq_send (from, message.data(), message.size(), 0);
    assert (rc >= 0);
    
    rc = zmq_close (to);
    assert (rc == 0);
    
    rc = zmq_close (from);
    assert (rc == 0);

    rc = zmq_ctx_destroy(context);
    assert (rc == 0);
    
    rc = zmq_ctx_destroy(context2);
    assert (rc == 0);
}

