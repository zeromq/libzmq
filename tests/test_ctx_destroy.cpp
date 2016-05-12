/*
    Copyright (c) 2007-2016 Contributors as noted in the AUTHORS file

    This file is part of libzmq, the ZeroMQ core engine in C++.

    libzmq is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License (LGPL) as published
    by the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    As a special exception, the Contributors give you permission to link
    this library with independent modules to produce an executable,
    regardless of the license terms of these independent modules, and to
    copy and distribute the resulting executable under terms of your choice,
    provided that you also meet, for each linked independent module, the
    terms and conditions of the license of that module. An independent
    module is a module which is not derived from or based on this library.
    If you modify this library, you must extend this exception to your
    version of the library.

    libzmq is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
    FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
    License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "testutil.hpp"

static void receiver (void *socket)
{
    char buffer[16];
    int rc = zmq_recv (socket, &buffer, sizeof (buffer), 0);
    assert(rc == -1);
}

void test_ctx_destroy()
{
    int rc;
    
    //  Set up our context and sockets
    void *ctx = zmq_ctx_new ();
    assert (ctx);
    
    void *socket = zmq_socket (ctx, ZMQ_PULL);
    assert (socket);

    // Close the socket
    rc = zmq_close (socket);
    assert (rc == 0);

    // Test error - API has multiple ways to kill Contexts
    rc = zmq_ctx_term (NULL);
    assert (rc == -1 && errno == EFAULT);
    rc = zmq_term (NULL);
    assert (rc == -1 && errno == EFAULT);

    // Destroy the context
    rc = zmq_ctx_destroy (ctx);
    assert (rc == 0);
}

void test_ctx_shutdown()
{
    int rc;
    
    //  Set up our context and sockets
    void *ctx = zmq_ctx_new ();
    assert (ctx);
    
    void *socket = zmq_socket (ctx, ZMQ_PULL);
    assert (socket);

    // Spawn a thread to receive on socket
    void *receiver_thread = zmq_threadstart (&receiver, socket);

    // Wait for thread to start up and block
    msleep (SETTLE_TIME);

    // Test error - Shutdown context
    rc = zmq_ctx_shutdown (NULL);
    assert (rc == -1 && errno == EFAULT);

    // Shutdown context, if we used destroy here we would deadlock.
    rc = zmq_ctx_shutdown (ctx);
    assert (rc == 0);

    // Wait for thread to finish
    zmq_threadclose (receiver_thread);

    // Close the socket.
    rc = zmq_close (socket);
    assert (rc == 0);

    // Destory the context, will now not hang as we have closed the socket.
    rc = zmq_ctx_destroy (ctx);
    assert (rc == 0);
}

int main (void)
{
    setup_test_environment();

    test_ctx_destroy();
    test_ctx_shutdown();

    return 0;
}
