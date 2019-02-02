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
#include "testutil_monitoring.hpp"

#include "testutil_unity.hpp"

void setUp ()
{
    setup_test_context ();
}

void tearDown ()
{
    teardown_test_context ();
}

void test_monitor_invalid_protocol_fails ()
{
    void *client = test_context_socket (ZMQ_DEALER);

    //  Socket monitoring only works over inproc://
    TEST_ASSERT_FAILURE_ERRNO (
      EPROTONOSUPPORT, zmq_socket_monitor (client, "tcp://127.0.0.1:*", 0));
}

void test_monitor_basic ()
{
    char my_endpoint[MAX_SOCKET_STRING];

    //  We'll monitor these two sockets
    void *client = test_context_socket (ZMQ_DEALER);
    void *server = test_context_socket (ZMQ_DEALER);

    //  Monitor all events on client and server sockets
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_socket_monitor (client, "inproc://monitor-client", ZMQ_EVENT_ALL));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_socket_monitor (server, "inproc://monitor-server", ZMQ_EVENT_ALL));

    //  Create two sockets for collecting monitor events
    void *client_mon = test_context_socket (ZMQ_PAIR);
    void *server_mon = test_context_socket (ZMQ_PAIR);

    //  Connect these to the inproc endpoints so they'll get events
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_connect (client_mon, "inproc://monitor-client"));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_connect (server_mon, "inproc://monitor-server"));

    //  Now do a basic ping test
    bind_loopback_ipv4 (server, my_endpoint, sizeof my_endpoint);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (client, my_endpoint));
    bounce (server, client);

    //  Close client and server
    //  TODO why does this use zero_linger?
    test_context_socket_close_zero_linger (client);
    test_context_socket_close_zero_linger (server);

    //  Now collect and check events from both sockets
    int event = get_monitor_event (client_mon, NULL, NULL);
    if (event == ZMQ_EVENT_CONNECT_DELAYED)
        event = get_monitor_event (client_mon, NULL, NULL);
    assert (event == ZMQ_EVENT_CONNECTED);
    expect_monitor_event (client_mon, ZMQ_EVENT_HANDSHAKE_SUCCEEDED);
    expect_monitor_event (client_mon, ZMQ_EVENT_MONITOR_STOPPED);

    //  This is the flow of server events
    expect_monitor_event (server_mon, ZMQ_EVENT_LISTENING);
    expect_monitor_event (server_mon, ZMQ_EVENT_ACCEPTED);
    expect_monitor_event (server_mon, ZMQ_EVENT_HANDSHAKE_SUCCEEDED);
    event = get_monitor_event (server_mon, NULL, NULL);
    //  Sometimes the server sees the client closing before it gets closed.
    if (event != ZMQ_EVENT_DISCONNECTED) {
        TEST_ASSERT_EQUAL_INT (ZMQ_EVENT_CLOSED, event);
        event = get_monitor_event (server_mon, NULL, NULL);
    }
    if (event != ZMQ_EVENT_DISCONNECTED) {
        TEST_ASSERT_EQUAL_INT (ZMQ_EVENT_MONITOR_STOPPED, event);
    }

    //  Close down the sockets
    //  TODO why does this use zero_linger?
    test_context_socket_close_zero_linger (client_mon);
    test_context_socket_close_zero_linger (server_mon);
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_monitor_invalid_protocol_fails);
    RUN_TEST (test_monitor_basic);
    return UNITY_END ();
}
