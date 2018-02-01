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
#include "testutil_security.hpp"

int main (void)
{
    setup_test_environment ();

    size_t len = MAX_SOCKET_STRING;
    char my_endpoint[MAX_SOCKET_STRING];
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    //  We'll monitor these two sockets
    void *client = zmq_socket (ctx, ZMQ_DEALER);
    assert (client);
    void *server = zmq_socket (ctx, ZMQ_DEALER);
    assert (server);

    //  Socket monitoring only works over inproc://
    int rc = zmq_socket_monitor (client, "tcp://127.0.0.1:*", 0);
    assert (rc == -1);
    assert (zmq_errno () == EPROTONOSUPPORT);

    //  Monitor all events on client and server sockets
    rc = zmq_socket_monitor (client, "inproc://monitor-client", ZMQ_EVENT_ALL);
    assert (rc == 0);
    rc = zmq_socket_monitor (server, "inproc://monitor-server", ZMQ_EVENT_ALL);
    assert (rc == 0);

    //  Create two sockets for collecting monitor events
    void *client_mon = zmq_socket (ctx, ZMQ_PAIR);
    assert (client_mon);
    void *server_mon = zmq_socket (ctx, ZMQ_PAIR);
    assert (server_mon);

    //  Connect these to the inproc endpoints so they'll get events
    rc = zmq_connect (client_mon, "inproc://monitor-client");
    assert (rc == 0);
    rc = zmq_connect (server_mon, "inproc://monitor-server");
    assert (rc == 0);

    //  Now do a basic ping test
    rc = zmq_bind (server, "tcp://127.0.0.1:*");
    assert (rc == 0);
    rc = zmq_getsockopt (server, ZMQ_LAST_ENDPOINT, my_endpoint, &len);
    assert (rc == 0);
    rc = zmq_connect (client, my_endpoint);
    assert (rc == 0);
    bounce (server, client);

    //  Close client and server
    close_zero_linger (client);
    close_zero_linger (server);

    //  Now collect and check events from both sockets
    int event = get_monitor_event (client_mon, NULL, NULL);
    if (event == ZMQ_EVENT_CONNECT_DELAYED)
        event = get_monitor_event (client_mon, NULL, NULL);
    assert (event == ZMQ_EVENT_CONNECTED);
#ifdef ZMQ_BUILD_DRAFT_API
    expect_monitor_event (client_mon, ZMQ_EVENT_HANDSHAKE_SUCCEEDED);
#endif
    expect_monitor_event (client_mon, ZMQ_EVENT_MONITOR_STOPPED);

    //  This is the flow of server events
    expect_monitor_event (server_mon, ZMQ_EVENT_LISTENING);
    expect_monitor_event (server_mon, ZMQ_EVENT_ACCEPTED);
#ifdef ZMQ_BUILD_DRAFT_API
    expect_monitor_event (server_mon, ZMQ_EVENT_HANDSHAKE_SUCCEEDED);
#endif
    event = get_monitor_event (server_mon, NULL, NULL);
    //  Sometimes the server sees the client closing before it gets closed.
    if (event != ZMQ_EVENT_DISCONNECTED) {
        assert (event == ZMQ_EVENT_CLOSED);
        event = get_monitor_event (server_mon, NULL, NULL);
    }
    if (event != ZMQ_EVENT_DISCONNECTED) {
        assert (event == ZMQ_EVENT_MONITOR_STOPPED);
    }

    //  Close down the sockets
    close_zero_linger (client_mon);
    close_zero_linger (server_mon);
    zmq_ctx_term (ctx);

    return 0;
}
