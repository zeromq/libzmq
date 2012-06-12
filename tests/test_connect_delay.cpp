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
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/


#include <assert.h>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <errno.h>

#include "../include/zmq.h"

int main (int argc, char *argv [])
{
    fprintf (stderr, "test_connect_delay running...\n");
    int val;
    int rc;
    char buffer[16];
    int seen = 0;

    void *context = zmq_ctx_new();
    assert (context);
    void *to = zmq_socket(context, ZMQ_PULL);
    assert (to);
    
    val = 0;
    rc = zmq_setsockopt(to, ZMQ_LINGER, &val, sizeof(val));
    assert (rc == 0);
    rc = zmq_bind(to, "tcp://*:5555");
    assert (rc == 0);

    //  Create a socket pushing to two endpoints - only 1 message should arrive.
    void *from = zmq_socket (context, ZMQ_PUSH);
    assert(from);
    
    val = 0;
    zmq_setsockopt (from, ZMQ_LINGER, &val, sizeof(val));
    rc = zmq_connect (from, "tcp://localhost:5556");
    assert (rc == 0);
    rc = zmq_connect (from, "tcp://localhost:5555");
    assert (rc == 0);

    for (int i = 0; i < 10; ++i)
    {
        std::string message("message ");
        message += ('0' + i);
        rc = zmq_send (from, message.data(), message.size(), 0);
        assert(rc >= 0);
    }
    
    sleep(1);
    seen = 0;
    for (int i = 0; i < 10; ++i)
    {
        memset(&buffer, 0, sizeof(buffer));
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
    
    context = zmq_ctx_new();
    std::cout << "  Rerunning with DELAY_ATTACH_ON_CONNECT\n";
    
    to = zmq_socket (context, ZMQ_PULL);
    assert (to);
    rc = zmq_bind (to, "tcp://*:5560");
    assert(rc == 0);
    
    val = 0;
    rc = zmq_setsockopt (to, ZMQ_LINGER, &val, sizeof(val));
    assert (rc == 0);
    
    //  Create a socket pushing to two endpoints - all messages should arrive.
    from = zmq_socket (context, ZMQ_PUSH);
    assert (from);
    
    val = 0;
    rc = zmq_setsockopt (from, ZMQ_LINGER, &val, sizeof(val));
    assert (rc == 0);
    
    val = 1;
    rc = zmq_setsockopt (from, ZMQ_DELAY_ATTACH_ON_CONNECT, &val, sizeof(val));
    assert (rc == 0);
    
    rc = zmq_connect (from, "tcp://localhost:5561");
    assert (rc == 0);
    
    rc = zmq_connect (from, "tcp://localhost:5560");
    assert (rc == 0);

    for (int i = 0; i < 10; ++i)
    {
        std::string message("message ");
        message += ('0' + i);
        rc = zmq_send (from, message.data(), message.size(), 0);
        assert (rc >= 0);
    }
    
    sleep(1);
    
    seen = 0;
    for (int i = 0; i < 10; ++i)
    {
        memset(&buffer, 0, sizeof(buffer));
        rc = zmq_recv (to, &buffer, sizeof(buffer), ZMQ_DONTWAIT);
        assert (rc != -1);
    }

    rc = zmq_close (from);
    assert (rc == 0);
    
    rc = zmq_close (to);
    assert (rc == 0);

    rc = zmq_ctx_destroy(context);
    assert (rc == 0);

    return 0;
}
