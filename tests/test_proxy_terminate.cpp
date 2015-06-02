/*
    Copyright (c) 2007-2015 Contributors as noted in the AUTHORS file

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
#include "../include/zmq_utils.h"

// This is a test for issue #1382. The server thread creates a SUB-PUSH
// steerable proxy. The main process then sends messages to the SUB
// but there is no pull on the other side, previously the proxy blocks
// in writing to the backend, preventing the proxy from terminating

void
server_task (void *ctx)
{
    // Frontend socket talks to main process
    void *frontend = zmq_socket (ctx, ZMQ_SUB);
    assert (frontend);
    int rc = zmq_setsockopt (frontend, ZMQ_SUBSCRIBE, "", 0);
    assert (rc == 0);
    rc = zmq_bind (frontend, "tcp://127.0.0.1:15564");
    assert (rc == 0);

    // Nice socket which is never read
    void *backend = zmq_socket (ctx, ZMQ_PUSH);
    assert (backend);
    rc = zmq_bind (backend, "tcp://127.0.0.1:15563");
    assert (rc == 0);

    // Control socket receives terminate command from main over inproc
    void *control = zmq_socket (ctx, ZMQ_SUB);
    assert (control);
    rc = zmq_setsockopt (control, ZMQ_SUBSCRIBE, "", 0);
    assert (rc == 0);
    rc = zmq_connect (control, "inproc://control");
    assert (rc == 0);

    // Connect backend to frontend via a proxy
    zmq_proxy_steerable (frontend, backend, NULL, control);

    rc = zmq_close (frontend);
    assert (rc == 0);
    rc = zmq_close (backend);
    assert (rc == 0);
    rc = zmq_close (control);
    assert (rc == 0);
}


// The main thread simply starts a basic steerable proxy server, publishes some messages, and then
// waits for the server to terminate.

int main (void)
{
    setup_test_environment ();

    void *ctx = zmq_ctx_new ();
    assert (ctx);
    // Control socket receives terminate command from main over inproc
    void *control = zmq_socket (ctx, ZMQ_PUB);
    assert (control);
    int rc = zmq_bind (control, "inproc://control");
    assert (rc == 0);

    void *thread = zmq_threadstart(&server_task, ctx);
    msleep (500); // Run for 500 ms

    // Start a secondary publisher which writes data to the SUB-PUSH server socket
    void *publisher = zmq_socket (ctx, ZMQ_PUB);
    assert (publisher);
    rc = zmq_connect (publisher, "tcp://127.0.0.1:15564");
    assert (rc == 0);

    msleep (50);
    rc = zmq_send (publisher, "This is a test", 14, 0);
    assert (rc == 14);

    msleep (50);
    rc = zmq_send (publisher, "This is a test", 14, 0);
    assert (rc == 14);

    msleep (50);
    rc = zmq_send (publisher, "This is a test", 14, 0);
    assert (rc == 14);
    rc = zmq_send (control, "TERMINATE", 9, 0);
    assert (rc == 9);

    rc = zmq_close (publisher);
    assert (rc == 0);
    rc = zmq_close (control);
    assert (rc == 0);

    zmq_threadclose (thread);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);
    return 0;
}
