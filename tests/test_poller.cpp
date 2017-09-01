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

// duplicated from fd.hpp
#ifdef ZMQ_HAVE_WINDOWS
#if defined _MSC_VER &&_MSC_VER <= 1400
    typedef UINT_PTR fd_t;
    enum {retired_fd = (fd_t)(~0)};
#else
    typedef SOCKET fd_t;
    enum {retired_fd = (fd_t)INVALID_SOCKET};
#endif
#else
    typedef int fd_t;
    enum {retired_fd = -1};
#endif

void test_null_poller_pointers (void *ctx)
{
    int rc = zmq_poller_destroy (NULL);
    assert (rc == -1 && errno == EFAULT);
    void *null_poller = NULL;
    rc = zmq_poller_destroy (&null_poller);
    assert (rc == -1 && errno == EFAULT);

    void *socket = zmq_socket (ctx, ZMQ_PAIR);
    assert (socket != NULL);

    rc = zmq_poller_add (NULL, socket, NULL, ZMQ_POLLIN);
    assert (rc == -1 && errno == EFAULT);
    rc = zmq_poller_add (&null_poller, socket, NULL, ZMQ_POLLIN);
    assert (rc == -1 && errno == EFAULT);

    rc = zmq_poller_modify (NULL, socket, ZMQ_POLLIN);
    assert (rc == -1 && errno == EFAULT);
    rc = zmq_poller_modify (&null_poller, socket, ZMQ_POLLIN);
    assert (rc == -1 && errno == EFAULT);

    rc = zmq_poller_remove (NULL, socket);
    assert (rc == -1 && errno == EFAULT);
    rc = zmq_poller_remove (&null_poller, socket);
    assert (rc == -1 && errno == EFAULT);

    fd_t fd;
    size_t fd_size = sizeof fd;
    rc = zmq_getsockopt(socket, ZMQ_FD, &fd, &fd_size);
    assert (rc == 0);

    rc = zmq_poller_add_fd (NULL, fd, NULL, ZMQ_POLLIN);
    assert (rc == -1 && errno == EFAULT);
    rc = zmq_poller_add_fd (&null_poller, fd, NULL, ZMQ_POLLIN);
    assert (rc == -1 && errno == EFAULT);

    rc = zmq_poller_modify_fd (NULL, fd, ZMQ_POLLIN);
    assert (rc == -1 && errno == EFAULT);
    rc = zmq_poller_modify_fd (&null_poller, fd, ZMQ_POLLIN);
    assert (rc == -1 && errno == EFAULT);

    rc = zmq_poller_remove_fd (NULL, fd);
    assert (rc == -1 && errno == EFAULT);
    rc = zmq_poller_remove_fd (&null_poller, fd);
    assert (rc == -1 && errno == EFAULT);

    zmq_poller_event_t event;
    rc = zmq_poller_wait (NULL, &event, 0);
    assert (rc == -1 && errno == EFAULT);
    rc = zmq_poller_wait (&null_poller, &event, 0);
    assert (rc == -1 && errno == EFAULT);

    rc = zmq_poller_wait_all (NULL, &event, 1, 0);
    assert (rc == -1 && errno == EFAULT);
    rc = zmq_poller_wait_all (&null_poller, &event, 1, 0);
    assert (rc == -1 && errno == EFAULT);

    rc = zmq_close (socket);
    assert (rc == 0);
}

void test_null_socket_pointers ()
{
    void *poller = zmq_poller_new ();
    assert (poller != NULL);

    int rc = zmq_poller_add (poller, NULL, NULL, ZMQ_POLLIN);
    assert (rc == -1 && errno == ENOTSOCK);

    rc = zmq_poller_modify (poller, NULL, ZMQ_POLLIN);
    assert (rc == -1 && errno == ENOTSOCK);

    rc = zmq_poller_remove (poller, NULL);
    assert (rc == -1 && errno == ENOTSOCK);

    fd_t null_socket_fd = retired_fd;
    
    rc = zmq_poller_add_fd (poller, null_socket_fd, NULL, ZMQ_POLLIN);
    assert (rc == -1 && errno == EBADF);

    rc = zmq_poller_modify_fd (poller, null_socket_fd, ZMQ_POLLIN);
    assert (rc == -1 && errno == EBADF);

    rc = zmq_poller_remove_fd (poller, null_socket_fd);
    assert (rc == -1 && errno == EBADF);

    rc = zmq_poller_destroy (&poller);
    assert (rc == 0);
}

void test_null_event_pointers (void *ctx)
{
    void *socket = zmq_socket (ctx, ZMQ_PAIR);
    assert (socket != NULL);

    void *poller = zmq_poller_new ();
    assert (poller != NULL);

    int rc = zmq_poller_add (poller, socket, NULL, ZMQ_POLLIN);
    assert (rc == 0);

    rc = zmq_poller_wait (poller, NULL, 0);
    assert (rc == -1 && errno == EFAULT);

    rc = zmq_poller_wait_all (poller, NULL, 1, 0);
    assert (rc == -1 && errno == EFAULT);

    //  TODO this causes an assertion, which is not consistent if the number 
    //  of events may be 0, the pointer should be allowed to by NULL in that 
    //  case too
#if 0
    rc = zmq_poller_wait_all (poller, NULL, 0, 0);
    assert (rc == 0);
#endif

    rc = zmq_poller_destroy (&poller);
    assert (rc == 0);

    rc = zmq_close (socket);
    assert (rc == 0);
}

void test_add_modify_remove_corner_cases(void *ctx)
{
    void *poller = zmq_poller_new ();
    assert (poller != NULL);

    void *zeromq_socket = zmq_socket (ctx, ZMQ_PAIR);
    assert (zeromq_socket != NULL);

    int rc = zmq_poller_add (poller, zeromq_socket, NULL, ZMQ_POLLIN);
    assert (rc == 0);

    //  attempt to add the same socket twice
    rc = zmq_poller_add (poller, zeromq_socket, NULL, ZMQ_POLLIN);
    assert (rc == -1 && errno == EINVAL);

    rc = zmq_poller_remove (poller, zeromq_socket);
    assert (rc == 0);

    //  attempt to remove socket that is not present
    rc = zmq_poller_remove (poller, zeromq_socket);
    assert (rc == -1 && errno == EINVAL);

    //  attempt to modify socket that is not present
    rc = zmq_poller_modify (poller, zeromq_socket, ZMQ_POLLIN);
    assert (rc == -1 && errno == EINVAL);

    //  add a socket with no events
    //  TODO should this really be legal? it does not make any sense...
    rc = zmq_poller_add (poller, zeromq_socket, NULL, 0);
    assert (rc == 0);

    fd_t plain_socket = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
    rc = zmq_poller_add_fd (poller, plain_socket, NULL, ZMQ_POLLIN);
    assert (rc == 0);

    //  attempt to add the same plain socket twice
    rc = zmq_poller_add_fd (poller, plain_socket, NULL, ZMQ_POLLIN);
    assert (rc == -1 && errno == EINVAL);

    rc = zmq_poller_remove_fd (poller, plain_socket);
    assert (rc == 0);

    //  attempt to remove plain socket that is not present
    rc = zmq_poller_remove_fd (poller, plain_socket);
    assert (rc == -1 && errno == EINVAL);

    //  attempt to modify plain socket that is not present
    rc = zmq_poller_modify_fd (poller, plain_socket, ZMQ_POLLIN);
    assert (rc == -1 && errno == EINVAL);

    rc = zmq_poller_destroy (&poller);
    assert (rc == 0);

    rc = zmq_close (zeromq_socket);
    assert (rc == 0);

    rc = close (plain_socket);
    assert (rc == 0);
}

void test_wait_corner_cases (void)
{
    void *poller = zmq_poller_new ();
    assert (poller != NULL);

    zmq_poller_event_t event;
    int rc = zmq_poller_wait(poller, &event, 0);
    assert (rc == -1 && errno == EAGAIN);

    //  this can never return since no socket was registered, and should yield an error
    rc = zmq_poller_wait(poller, &event, -1);
    assert (rc == -1 && errno == EFAULT);

    rc = zmq_poller_wait_all (poller, &event, -1, 0);
    assert (rc == -1 && errno == EINVAL);

    rc = zmq_poller_wait_all (poller, &event, 0, 0);
    assert (rc == -1 && errno == EAGAIN);

    //  this can never return since no socket was registered, and should yield an error
    rc = zmq_poller_wait_all (poller, &event, 0, -1);
    assert (rc == -1 && errno == EFAULT);

    rc = zmq_poller_destroy (&poller);
    assert (rc == 0);
}

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
    void *poller = zmq_poller_new ();
    zmq_poller_event_t event;

    // waiting on poller with no registered sockets should report error
    rc = zmq_poller_wait (poller, &event, 0);
    assert (rc == -1);
    assert (errno == EAGAIN);

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
    assert (errno == EAGAIN);

    //  Stop polling sink
    rc = zmq_poller_remove (poller, sink);
    assert (rc == 0);

    //  Check we can poll an FD
    rc = zmq_connect (bowl, my_endpoint_0);
    assert (rc == 0);

    fd_t fd;
    size_t fd_size = sizeof (fd);

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

    //  Destroy sockets, poller and ctx
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

    test_null_poller_pointers (ctx);
    test_null_socket_pointers ();
    test_null_event_pointers (ctx);

    test_add_modify_remove_corner_cases (ctx);
    test_wait_corner_cases ();

    rc = zmq_poller_destroy (&poller);
    assert (rc == 0);
    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    return 0;
}
