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



// This is our server task.
// It runs a proxy with a single REP socket as both frontend and backend.

void
server_task (void *ctx)
{
    size_t len = MAX_SOCKET_STRING;
    char my_endpoint[MAX_SOCKET_STRING];
    void *rep = zmq_socket (ctx, ZMQ_REP);
    assert (rep);
    int rc = zmq_bind (rep, "tcp://127.0.0.1:*");
    assert (rc == 0);
    rc = zmq_getsockopt (rep, ZMQ_LAST_ENDPOINT, my_endpoint, &len);
    assert (rc == 0);

    // Control socket receives terminate command from main over inproc
    void *control = zmq_socket (ctx, ZMQ_REQ);
    assert (control);
    rc = zmq_connect (control, "inproc://control");
    assert (rc == 0);
    rc = s_send (control, my_endpoint);
    assert (rc > 0);

    // Use rep as both frontend and backend
    rc = zmq_proxy_steerable (rep, rep, NULL, control);
    assert (rc == 0);

    rc = zmq_close (rep);
    assert (rc == 0);
    rc = zmq_close (control);
    assert (rc == 0);
}


// The main thread simply starts several clients and a server, and then
// waits for the server to finish.

int main (void)
{
    setup_test_environment ();

    void *ctx = zmq_ctx_new ();
    assert (ctx);

    void *server_thread = zmq_threadstart(&server_task, ctx);

    // Control socket receives terminate command from main over inproc
    void *control = zmq_socket (ctx, ZMQ_REP);
    assert (control);
    int rc = zmq_bind (control, "inproc://control");
    assert (rc == 0);
    char *my_endpoint = s_recv (control);
    assert (my_endpoint);

    // client socket pings proxy over tcp
    void *req = zmq_socket (ctx, ZMQ_REQ);
    assert (req);
    rc = zmq_connect (req, my_endpoint);
    assert (rc == 0);

    char buf[255];
    rc = zmq_send(req, "msg1", 4, 0);
    assert (rc == 4);
    rc = zmq_recv(req, buf, 255, 0);
    assert (rc == 4);
    assert (memcmp (buf, "msg1", 4) == 0);

    rc = zmq_send(req, "msg22", 5, 0);
    assert (rc == 5);
    rc = zmq_recv(req, buf, 255, 0);
    assert (rc == 5);
    assert (memcmp (buf, "msg22", 5) == 0);

    rc = zmq_send (control, "TERMINATE", 9, 0);
    assert (rc == 9);

    rc = zmq_close (control);
    assert (rc == 0);
    rc = zmq_close (req);
    assert (rc == 0);
    free (my_endpoint);

    zmq_threadclose (server_thread);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);
    return 0;
}
