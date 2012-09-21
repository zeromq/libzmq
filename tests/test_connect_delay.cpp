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
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <string>
#include <pthread.h>

#undef NDEBUG
#include <assert.h>

static void *server (void *)
{
    void *socket, *context;
    char buffer[16];
    int rc, val;

    context = zmq_init (1);
    assert (context);

    socket = zmq_socket (context, ZMQ_PULL);
    assert (socket);

    val = 0;
    rc = zmq_setsockopt(socket, ZMQ_LINGER, &val, sizeof(val));
    assert (rc == 0);

    rc = zmq_bind (socket, "ipc:///tmp/recon");
    assert (rc == 0);

    memset (&buffer, 0, sizeof(buffer));
    rc = zmq_recv (socket, &buffer, sizeof(buffer), 0);

    // Intentionally bail out
    rc = zmq_close (socket);
    assert (rc == 0);

    rc = zmq_term (context);
    assert (rc == 0);

    usleep (200000);

    context = zmq_init (1);
    assert (context);

    socket = zmq_socket (context, ZMQ_PULL);
    assert (socket);

    val = 0;
    rc = zmq_setsockopt(socket, ZMQ_LINGER, &val, sizeof(val));
    assert (rc == 0);

    rc = zmq_bind (socket, "ipc:///tmp/recon");
    assert (rc == 0);

    usleep (200000);

    memset (&buffer, 0, sizeof(buffer));
    rc = zmq_recv (socket, &buffer, sizeof(buffer), ZMQ_DONTWAIT);
    assert (rc != -1);

    // Start closing the socket while the connecting process is underway.
    rc = zmq_close (socket);
    assert (rc == 0);

    rc = zmq_term (context);
    assert (rc == 0);

    pthread_exit(NULL);
}

static void *worker (void *)
{
    void *socket, *context;
    int rc, hadone, val;

    context = zmq_init (1);
    assert (context);

    socket = zmq_socket (context, ZMQ_PUSH);
    assert (socket);

    val = 0;
    rc = zmq_setsockopt(socket, ZMQ_LINGER, &val, sizeof(val));
    assert (rc == 0);

    val = 1;
    rc = zmq_setsockopt (socket, ZMQ_DELAY_ATTACH_ON_CONNECT, &val, sizeof(val));
    assert (rc == 0);

    rc = zmq_connect (socket, "ipc:///tmp/recon");
    assert (rc == 0);

    hadone = 0;
    // Not checking RC as some may be -1
    for (int i = 0; i < 6; i++) {
        usleep(200000);
        rc = zmq_send (socket, "hi", 2, ZMQ_DONTWAIT);
        if (rc != -1)
            hadone ++;
    }

    assert (hadone >= 2);
    assert (hadone < 4);

    rc = zmq_close (socket);
    assert (rc == 0);

    rc = zmq_term (context);
    assert (rc == 0);

    pthread_exit(NULL);
}

int main (void)
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

    // Create a socket pushing to two endpoints - only 1 message should arrive.
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

    context = zmq_ctx_new();
    fprintf (stderr, " Rerunning with DELAY_ATTACH_ON_CONNECT\n");

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

    fprintf (stderr, " Running DELAY_ATTACH_ON_CONNECT with disconnect\n");

    pthread_t serv, work;

    rc = pthread_create (&serv, NULL, server, NULL);
    assert (rc == 0);

    rc = pthread_create (&work, NULL, worker, NULL);
    assert (rc == 0);
    
    pthread_exit(NULL);
}
