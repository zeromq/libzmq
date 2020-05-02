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

#include <stdlib.h>
#include <string.h>

SETUP_TEARDOWN_TESTCONTEXT

void test_monitor_invalid_protocol_fails ()
{
    void *client = test_context_socket (ZMQ_DEALER);

    //  Socket monitoring only works over inproc://
    TEST_ASSERT_FAILURE_ERRNO (
      EPROTONOSUPPORT, zmq_socket_monitor (client, "tcp://127.0.0.1:*", 0));

#ifdef ZMQ_EVENT_PIPES_STATS
    //  Stats command needs to be called on a valid socket with monitoring
    //  enabled
    TEST_ASSERT_FAILURE_ERRNO (ENOTSOCK, zmq_socket_monitor_pipes_stats (NULL));
    TEST_ASSERT_FAILURE_ERRNO (EINVAL, zmq_socket_monitor_pipes_stats (client));
#endif

    test_context_socket_close_zero_linger (client);
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
    TEST_ASSERT_EQUAL_INT (ZMQ_EVENT_CONNECTED, event);
    expect_monitor_event (client_mon, ZMQ_EVENT_HANDSHAKE_SUCCEEDED);
    event = get_monitor_event (client_mon, NULL, NULL);
    if (event == ZMQ_EVENT_DISCONNECTED) {
        expect_monitor_event (client_mon, ZMQ_EVENT_CONNECT_RETRIED);
        expect_monitor_event (client_mon, ZMQ_EVENT_MONITOR_STOPPED);
    } else
        TEST_ASSERT_EQUAL_INT (ZMQ_EVENT_MONITOR_STOPPED, event);

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
    //  TODO: When not waiting until the monitor stopped, the I/O thread runs
    //  into some deadlock. This must be fixed, but until it is fixed, we wait
    //  here in order to have more reliable test execution.
    while (event != ZMQ_EVENT_MONITOR_STOPPED) {
        event = get_monitor_event (server_mon, NULL, NULL);
    }

    //  Close down the sockets
    //  TODO why does this use zero_linger?
    test_context_socket_close_zero_linger (client_mon);
    test_context_socket_close_zero_linger (server_mon);
}

#if (defined ZMQ_CURRENT_EVENT_VERSION && ZMQ_CURRENT_EVENT_VERSION >= 2)      \
  || (defined ZMQ_CURRENT_EVENT_VERSION                                        \
      && ZMQ_CURRENT_EVENT_VERSION_DRAFT >= 2)
void test_monitor_versioned_invalid_socket_type ()
{
    void *client = test_context_socket (ZMQ_DEALER);

    //  Socket monitoring only works with ZMQ_PAIR, ZMQ_PUB and ZMQ_PUSH.
    TEST_ASSERT_FAILURE_ERRNO (
      EINVAL, zmq_socket_monitor_versioned (
                client, "inproc://invalid-socket-type", 0, 2, ZMQ_CLIENT));

    test_context_socket_close_zero_linger (client);
}

void test_monitor_versioned_basic (bind_function_t bind_function_,
                                   const char *expected_prefix_,
                                   int type_)
{
    char server_endpoint[MAX_SOCKET_STRING];
    char client_mon_endpoint[MAX_SOCKET_STRING];
    char server_mon_endpoint[MAX_SOCKET_STRING];

    //  Create a unique endpoint for each call so we don't have
    //  to wait for the sockets to unbind.
    snprintf (client_mon_endpoint, MAX_SOCKET_STRING, "inproc://client%s%d",
              expected_prefix_, type_);
    snprintf (server_mon_endpoint, MAX_SOCKET_STRING, "inproc://server%s%d",
              expected_prefix_, type_);

    //  We'll monitor these two sockets
    void *client = test_context_socket (ZMQ_DEALER);
    void *server = test_context_socket (ZMQ_DEALER);

    //  Monitor all events on client and server sockets
    TEST_ASSERT_SUCCESS_ERRNO (zmq_socket_monitor_versioned (
      client, client_mon_endpoint, ZMQ_EVENT_ALL_V2, 2, type_));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_socket_monitor_versioned (
      server, server_mon_endpoint, ZMQ_EVENT_ALL_V2, 2, type_));

    //  Choose the appropriate consumer socket type.
    int mon_type = ZMQ_PAIR;
    switch (type_) {
        case ZMQ_PAIR:
            mon_type = ZMQ_PAIR;
            break;
        case ZMQ_PUSH:
            mon_type = ZMQ_PULL;
            break;
        case ZMQ_PUB:
            mon_type = ZMQ_SUB;
            break;
    }

    //  Create two sockets for collecting monitor events
    void *client_mon = test_context_socket (mon_type);
    void *server_mon = test_context_socket (mon_type);

    //  Additionally subscribe to all events if a PUB socket is used.
    if (type_ == ZMQ_PUB) {
        TEST_ASSERT_SUCCESS_ERRNO (
          zmq_setsockopt (client_mon, ZMQ_SUBSCRIBE, "", 0));
        TEST_ASSERT_SUCCESS_ERRNO (
          zmq_setsockopt (server_mon, ZMQ_SUBSCRIBE, "", 0));
    }

    //  Connect these to the inproc endpoints so they'll get events
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (client_mon, client_mon_endpoint));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (server_mon, server_mon_endpoint));

    //  Now do a basic ping test
    bind_function_ (server, server_endpoint, sizeof server_endpoint);

    int ipv6;
    size_t ipv6_size = sizeof (ipv6);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (server, ZMQ_IPV6, &ipv6, &ipv6_size));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (client, ZMQ_IPV6, &ipv6, sizeof (int)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (client, server_endpoint));
    bounce (server, client);

    //  Close client and server
    //  TODO why does this use zero_linger?
    test_context_socket_close_zero_linger (client);
    test_context_socket_close_zero_linger (server);

    char *client_local_address = NULL;
    char *client_remote_address = NULL;

    //  Now collect and check events from both sockets
    int64_t event = get_monitor_event_v2 (
      client_mon, NULL, &client_local_address, &client_remote_address);
    if (event == ZMQ_EVENT_CONNECT_DELAYED) {
        free (client_local_address);
        free (client_remote_address);
        event = get_monitor_event_v2 (client_mon, NULL, &client_local_address,
                                      &client_remote_address);
    }
    TEST_ASSERT_EQUAL (ZMQ_EVENT_CONNECTED, event);
    TEST_ASSERT_EQUAL_STRING (server_endpoint, client_remote_address);
    TEST_ASSERT_EQUAL_STRING_LEN (expected_prefix_, client_local_address,
                                  strlen (expected_prefix_));
    TEST_ASSERT_NOT_EQUAL (
      0, strcmp (client_local_address, client_remote_address));

    expect_monitor_event_v2 (client_mon, ZMQ_EVENT_HANDSHAKE_SUCCEEDED,
                             client_local_address, client_remote_address);
    event = get_monitor_event_v2 (client_mon, NULL, NULL, NULL);
    if (event == ZMQ_EVENT_DISCONNECTED) {
        expect_monitor_event_v2 (client_mon, ZMQ_EVENT_CONNECT_RETRIED,
                                 client_local_address, client_remote_address);
        expect_monitor_event_v2 (client_mon, ZMQ_EVENT_MONITOR_STOPPED, "", "");
    } else
        TEST_ASSERT_EQUAL_INT (ZMQ_EVENT_MONITOR_STOPPED, event);

    //  This is the flow of server events
    expect_monitor_event_v2 (server_mon, ZMQ_EVENT_LISTENING,
                             client_remote_address, "");
    expect_monitor_event_v2 (server_mon, ZMQ_EVENT_ACCEPTED,
                             client_remote_address, client_local_address);
    expect_monitor_event_v2 (server_mon, ZMQ_EVENT_HANDSHAKE_SUCCEEDED,
                             client_remote_address, client_local_address);
    event = get_monitor_event_v2 (server_mon, NULL, NULL, NULL);
    //  Sometimes the server sees the client closing before it gets closed.
    if (event != ZMQ_EVENT_DISCONNECTED) {
        TEST_ASSERT_EQUAL_INT (ZMQ_EVENT_CLOSED, event);
        event = get_monitor_event_v2 (server_mon, NULL, NULL, NULL);
    }
    if (event != ZMQ_EVENT_DISCONNECTED) {
        TEST_ASSERT_EQUAL_INT (ZMQ_EVENT_MONITOR_STOPPED, event);
    }
    //  TODO: When not waiting until the monitor stopped, the I/O thread runs
    //  into some deadlock. This must be fixed, but until it is fixed, we wait
    //  here in order to have more reliable test execution.
    while (event != ZMQ_EVENT_MONITOR_STOPPED) {
        event = get_monitor_event_v2 (server_mon, NULL, NULL, NULL);
    }
    free (client_local_address);
    free (client_remote_address);

    //  Close down the sockets
    //  TODO why does this use zero_linger?
    test_context_socket_close_zero_linger (client_mon);
    test_context_socket_close_zero_linger (server_mon);
}

void test_monitor_versioned_basic_tcp_ipv4 ()
{
    static const char prefix[] = "tcp://127.0.0.1:";
    test_monitor_versioned_basic (bind_loopback_ipv4, prefix, ZMQ_PAIR);
    test_monitor_versioned_basic (bind_loopback_ipv4, prefix, ZMQ_PUB);
    test_monitor_versioned_basic (bind_loopback_ipv4, prefix, ZMQ_PUSH);
}

void test_monitor_versioned_basic_tcp_ipv6 ()
{
    static const char prefix[] = "tcp://[::1]:";
    test_monitor_versioned_basic (bind_loopback_ipv6, prefix, ZMQ_PAIR);
    test_monitor_versioned_basic (bind_loopback_ipv6, prefix, ZMQ_PUB);
    test_monitor_versioned_basic (bind_loopback_ipv6, prefix, ZMQ_PUSH);
}

void test_monitor_versioned_basic_ipc ()
{
    static const char prefix[] = "ipc://";
    test_monitor_versioned_basic (bind_loopback_ipc, prefix, ZMQ_PAIR);
    test_monitor_versioned_basic (bind_loopback_ipc, prefix, ZMQ_PUB);
    test_monitor_versioned_basic (bind_loopback_ipc, prefix, ZMQ_PUSH);
}

void test_monitor_versioned_basic_tipc ()
{
    static const char prefix[] = "tipc://";
    test_monitor_versioned_basic (bind_loopback_tipc, prefix, ZMQ_PAIR);
    test_monitor_versioned_basic (bind_loopback_tipc, prefix, ZMQ_PUB);
    test_monitor_versioned_basic (bind_loopback_tipc, prefix, ZMQ_PUSH);
}

#ifdef ZMQ_EVENT_PIPES_STATS
void test_monitor_versioned_stats (bind_function_t bind_function_,
                                   const char *expected_prefix_)
{
    char server_endpoint[MAX_SOCKET_STRING];
    const int pulls_count = 4;
    void *pulls[pulls_count];

    //  We'll monitor these two sockets
    void *push = test_context_socket (ZMQ_PUSH);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_socket_monitor_versioned (
      push, "inproc://monitor-push", ZMQ_EVENT_PIPES_STATS, 2, ZMQ_PAIR));

    //  Should fail if there are no pipes to monitor
    TEST_ASSERT_FAILURE_ERRNO (EAGAIN, zmq_socket_monitor_pipes_stats (push));

    void *push_mon = test_context_socket (ZMQ_PAIR);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (push_mon, "inproc://monitor-push"));

    //  Set lower HWM - queues will be filled so we should see it in the stats
    int send_hwm = 500;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (push, ZMQ_SNDHWM, &send_hwm, sizeof (send_hwm)));
    //  Set very low TCP buffers so that messages cannot be stored in-flight
    const int tcp_buffer_size = 4096;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      push, ZMQ_SNDBUF, &tcp_buffer_size, sizeof (tcp_buffer_size)));
    bind_function_ (push, server_endpoint, sizeof (server_endpoint));

    int ipv6;
    size_t ipv6_size = sizeof (ipv6);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (push, ZMQ_IPV6, &ipv6, &ipv6_size));
    for (int i = 0; i < pulls_count; ++i) {
        pulls[i] = test_context_socket (ZMQ_PULL);
        TEST_ASSERT_SUCCESS_ERRNO (
          zmq_setsockopt (pulls[i], ZMQ_IPV6, &ipv6, sizeof (int)));
        int timeout_ms = 10;
        TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
          pulls[i], ZMQ_RCVTIMEO, &timeout_ms, sizeof (timeout_ms)));
        TEST_ASSERT_SUCCESS_ERRNO (
          zmq_setsockopt (pulls[i], ZMQ_RCVHWM, &send_hwm, sizeof (send_hwm)));
        TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
          pulls[i], ZMQ_RCVBUF, &tcp_buffer_size, sizeof (tcp_buffer_size)));
        TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (pulls[i], server_endpoint));
    }

    //  Send until we block
    int send_count = 0;
    //  Saturate the TCP buffers too
    char data[tcp_buffer_size * 2];
    memset (data, 0, sizeof (data));
    //  Saturate all pipes - send + receive - on all connections
    while (send_count < send_hwm * 2 * pulls_count) {
        TEST_ASSERT_EQUAL_INT (sizeof (data),
                               zmq_send (push, data, sizeof (data), 0));
        ++send_count;
    }

    //  Drain one of the pulls - doesn't matter how many messages, at least one
    send_count = send_count / 4;
    do {
        zmq_recv (pulls[0], data, sizeof (data), 0);
        --send_count;
    } while (send_count > 0);

    //  To kick the application thread, do a dummy getsockopt - users here
    //  should use the monitor and the other sockets in a poll.
    unsigned long int dummy;
    size_t dummy_size = sizeof (dummy);
    msleep (SETTLE_TIME);
    //  Note that the pipe stats on the sender will not get updated until the
    //  receiver has processed at least lwm ((hwm + 1) / 2) messages AND until
    //  the application thread has ran through the mailbox, as the update is
    //  delivered via a message (send_activate_write)
    zmq_getsockopt (push, ZMQ_EVENTS, &dummy, &dummy_size);

    //  Ask for stats and check that they match
    zmq_socket_monitor_pipes_stats (push);

    msleep (SETTLE_TIME);
    zmq_getsockopt (push, ZMQ_EVENTS, &dummy, &dummy_size);

    for (int i = 0; i < pulls_count; ++i) {
        char *push_local_address = NULL;
        char *push_remote_address = NULL;
        uint64_t queue_stat[2];
        int64_t event = get_monitor_event_v2 (
          push_mon, queue_stat, &push_local_address, &push_remote_address);
        TEST_ASSERT_EQUAL_STRING (server_endpoint, push_local_address);
        TEST_ASSERT_EQUAL_STRING_LEN (expected_prefix_, push_remote_address,
                                      strlen (expected_prefix_));
        TEST_ASSERT_EQUAL_INT (ZMQ_EVENT_PIPES_STATS, event);
        TEST_ASSERT_EQUAL_INT (i == 0 ? 0 : send_hwm, queue_stat[0]);
        TEST_ASSERT_EQUAL_INT (0, queue_stat[1]);
        free (push_local_address);
        free (push_remote_address);
    }

    //  Close client and server
    test_context_socket_close_zero_linger (push_mon);
    test_context_socket_close_zero_linger (push);
    for (int i = 0; i < pulls_count; ++i)
        test_context_socket_close_zero_linger (pulls[i]);
}

void test_monitor_versioned_stats_tcp_ipv4 ()
{
    static const char prefix[] = "tcp://127.0.0.1:";
    test_monitor_versioned_stats (bind_loopback_ipv4, prefix);
}

void test_monitor_versioned_stats_tcp_ipv6 ()
{
    static const char prefix[] = "tcp://[::1]:";
    test_monitor_versioned_stats (bind_loopback_ipv6, prefix);
}

void test_monitor_versioned_stats_ipc ()
{
    static const char prefix[] = "ipc://";
    test_monitor_versioned_stats (bind_loopback_ipc, prefix);
}
#endif // ZMQ_EVENT_PIPES_STATS
#endif

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_monitor_invalid_protocol_fails);
    RUN_TEST (test_monitor_basic);

#if (defined ZMQ_CURRENT_EVENT_VERSION && ZMQ_CURRENT_EVENT_VERSION >= 2)      \
  || (defined ZMQ_CURRENT_EVENT_VERSION                                        \
      && ZMQ_CURRENT_EVENT_VERSION_DRAFT >= 2)
    RUN_TEST (test_monitor_versioned_invalid_socket_type);
    RUN_TEST (test_monitor_versioned_basic_tcp_ipv4);
    RUN_TEST (test_monitor_versioned_basic_tcp_ipv6);
    RUN_TEST (test_monitor_versioned_basic_ipc);
    RUN_TEST (test_monitor_versioned_basic_tipc);
#ifdef ZMQ_EVENT_PIPES_STATS
    RUN_TEST (test_monitor_versioned_stats_tcp_ipv4);
    RUN_TEST (test_monitor_versioned_stats_tcp_ipv6);
    RUN_TEST (test_monitor_versioned_stats_ipc);
#endif
#endif

    return UNITY_END ();
}
