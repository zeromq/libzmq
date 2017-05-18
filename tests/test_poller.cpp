/*
    Copyright (c) 2007-2017 Contributors as noted in the AUTHORS file

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

int main (void)
{
    size_t len = MAX_SOCKET_STRING;
    char my_endpoint_0[MAX_SOCKET_STRING];
    char my_endpoint_1[MAX_SOCKET_STRING];

    setup_test_environment ();

    void *ctx = zmq_ctx_new ();
    assert (ctx);

    //  Create few sockets
    void *vent = zmq_socket (ctx, ZMQ_PUSH);
    assert (vent);
    int rc = zmq_bind (vent, "tcp://127.0.0.1:*");
    assert (rc == 0);
    rc = zmq_getsockopt (vent, ZMQ_LAST_ENDPOINT, my_endpoint_0, &len);
    assert (rc == 0);

    void *sink = zmq_socket (ctx, ZMQ_PULL);
    assert (sink);
    rc = zmq_connect (sink, my_endpoint_0);
    assert (rc == 0);

    void *bowl = zmq_socket (ctx, ZMQ_PULL);
    assert (bowl);

#if defined(ZMQ_SERVER) && defined(ZMQ_CLIENT)
    void *server = zmq_socket (ctx, ZMQ_SERVER);
    assert (server);
    rc = zmq_bind (server, "tcp://127.0.0.1:*");
    assert (rc == 0);
    len = MAX_SOCKET_STRING;
    rc = zmq_getsockopt (server, ZMQ_LAST_ENDPOINT, my_endpoint_1, &len);
    assert (rc == 0);

    void *client = zmq_socket (ctx, ZMQ_CLIENT);
    assert (client);
#endif

    //  Set up poller
    void* poller = zmq_poller_new ();
    zmq_poller_event_t event;

    // waiting on poller with no registered sockets should report error
    rc = zmq_poller_wait(poller, &event, 0);
    assert (rc == -1);
    assert (errno == ETIMEDOUT);

    // register sink
    rc = zmq_poller_add (poller, sink, sink, ZMQ_POLLIN);
    assert (rc == 0);
    
    //  Send a message
    char data[1] = {'H'};
    rc = zmq_send_const (vent, data, 1, 0);
    assert (rc == 1);   

    //  We expect a message only on the sink
    rc = zmq_poller_wait (poller, &event, -1);
    assert (rc == 0);
    assert (event.socket == sink);
    assert (event.user_data == sink);
    rc = zmq_recv (sink, data, 1, 0);
    assert (rc == 1);

    //  We expect timed out
    rc = zmq_poller_wait (poller, &event, 0);
    assert (rc == -1);
    assert (errno == ETIMEDOUT);

    //  Stop polling sink
    rc = zmq_poller_remove (poller, sink);
    assert (rc == 0);

    //  Check we can poll an FD
    rc = zmq_connect (bowl, my_endpoint_0);
    assert (rc == 0);

#if defined _WIN32
    SOCKET fd;
    size_t fd_size = sizeof (SOCKET);
#else 
    int fd;
    size_t fd_size = sizeof (int);
#endif

    rc = zmq_getsockopt (bowl, ZMQ_FD, &fd, &fd_size);
    assert (rc == 0);
    rc = zmq_poller_add_fd (poller, fd, bowl, ZMQ_POLLIN);
    assert (rc == 0);
    rc = zmq_poller_wait (poller, &event, 500);
    assert (rc == 0);
    assert (event.socket == NULL);
    assert (event.fd == fd);
    assert (event.user_data == bowl);
    zmq_poller_remove_fd (poller, fd);

#if defined(ZMQ_SERVER) && defined(ZMQ_CLIENT)
    //  Polling on thread safe sockets
    rc = zmq_poller_add (poller, server, NULL, ZMQ_POLLIN);
    assert (rc == 0);
    rc = zmq_connect (client, my_endpoint_1);
    assert (rc == 0);
    rc = zmq_send_const (client, data, 1, 0);
    assert (rc == 1);
    rc = zmq_poller_wait (poller, &event, 500);
    assert (rc == 0);
    assert (event.socket == server);
    assert (event.user_data == NULL); 
    rc = zmq_recv (server, data, 1, 0);
    assert (rc == 1);    

    //  Polling on pollout
    rc = zmq_poller_modify (poller, server, ZMQ_POLLOUT | ZMQ_POLLIN); 
    assert (rc == 0);
    rc = zmq_poller_wait (poller, &event, 0);
    assert (rc == 0);
    assert (event.socket == server);
    assert (event.user_data == NULL);
    assert (event.events == ZMQ_POLLOUT);

    //  Stop polling server
    rc = zmq_poller_remove (poller, server);
    assert (rc == 0);
#endif

    //  Destory sockets, poller and ctx    
    rc = zmq_close (sink);
    assert (rc == 0);
    rc = zmq_close (vent);
    assert (rc == 0);
    rc = zmq_close (bowl);
    assert (rc == 0);
#if defined(ZMQ_SERVER) && defined(ZMQ_CLIENT)
    rc = zmq_close (server);
    assert (rc == 0);
    rc = zmq_close (client);
    assert (rc == 0);
#endif

    // Test error - null poller pointers
    rc = zmq_poller_destroy (NULL);
    assert (rc == -1 && errno == EFAULT);
    void *null_poller = NULL;
    rc = zmq_poller_destroy (&null_poller);
    assert (rc == -1 && errno == EFAULT);

    rc = zmq_poller_destroy (&poller);
    assert(rc == 0);
    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    return 0;
}
