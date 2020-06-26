/*
    Copyright (c) 2017 Contributors as noted in the AUTHORS file

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
#include <assert.h>

#include "testutil.hpp"
#include "testutil_unity.hpp"
#include "testutil_monitoring.hpp"

#include <unity.h>

// test behavior with (mostly) default values
void reconnect_default ()
{
    // setup pub socket
    void *pub = test_context_socket (ZMQ_PUB);
    //  Bind pub socket
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (pub, ENDPOINT_0));

    // setup sub socket
    void *sub = test_context_socket (ZMQ_SUB);
    //  Monitor all events on sub
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_socket_monitor (sub, "inproc://monitor-sub", ZMQ_EVENT_ALL));
    //  Create socket for collecting monitor events
    void *sub_mon = test_context_socket (ZMQ_PAIR);
    //  Connect so they'll get events
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sub_mon, "inproc://monitor-sub"));
    // set reconnect interval so only a single reconnect is tried
    int interval = 60 * 1000;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sub, ZMQ_RECONNECT_IVL, &interval, sizeof (interval)));
    // connect to pub
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sub, ENDPOINT_0));

    //  confirm that we get following events
    expect_monitor_event (sub_mon, ZMQ_EVENT_CONNECT_DELAYED);
    expect_monitor_event (sub_mon, ZMQ_EVENT_CONNECTED);
    expect_monitor_event (sub_mon, ZMQ_EVENT_HANDSHAKE_SUCCEEDED);

    // close the pub socket
    test_context_socket_close_zero_linger (pub);

    //  confirm that we get following events
    expect_monitor_event (sub_mon, ZMQ_EVENT_DISCONNECTED);
    expect_monitor_event (sub_mon, ZMQ_EVENT_CONNECT_RETRIED);

    // ZMQ_EVENT_CONNECT_RETRIED should be last event, because of timeout set above
    int event;
    char *event_address;
    int rc = get_monitor_event_with_timeout (sub_mon, &event, &event_address,
                                             2 * 1000);
    assert (rc == -1);

    //  Close sub
    //  TODO why does this use zero_linger?
    test_context_socket_close_zero_linger (sub);

    //  Close monitor
    //  TODO why does this use zero_linger?
    test_context_socket_close_zero_linger (sub_mon);
}


// test successful reconnect
void reconnect_success ()
{
    // setup pub socket
    void *pub = test_context_socket (ZMQ_PUB);
    //  Bind pub socket
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (pub, ENDPOINT_0));

    // setup sub socket
    void *sub = test_context_socket (ZMQ_SUB);
    //  Monitor all events on sub
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_socket_monitor (sub, "inproc://monitor-sub", ZMQ_EVENT_ALL));
    //  Create socket for collecting monitor events
    void *sub_mon = test_context_socket (ZMQ_PAIR);
    //  Connect so they'll get events
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sub_mon, "inproc://monitor-sub"));
    // set reconnect interval so only a single reconnect is tried
    int interval = 1 * 1000;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sub, ZMQ_RECONNECT_IVL, &interval, sizeof (interval)));
    // connect to pub
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sub, ENDPOINT_0));

    //  confirm that we get following events
    expect_monitor_event (sub_mon, ZMQ_EVENT_CONNECT_DELAYED);
    expect_monitor_event (sub_mon, ZMQ_EVENT_CONNECTED);
    expect_monitor_event (sub_mon, ZMQ_EVENT_HANDSHAKE_SUCCEEDED);

    // close the pub socket
    test_context_socket_close_zero_linger (pub);

    //  confirm that we get following events
    expect_monitor_event (sub_mon, ZMQ_EVENT_DISCONNECTED);
    expect_monitor_event (sub_mon, ZMQ_EVENT_CONNECT_RETRIED);

    // ZMQ_EVENT_CONNECT_RETRIED should be last event, because of timeout set above
    int event;
    char *event_address;
    int rc = get_monitor_event_with_timeout (sub_mon, &event, &event_address,
                                             SETTLE_TIME);
    assert (rc == -1);

    //  Now re-bind pub socket and wait for re-connect
    pub = test_context_socket (ZMQ_PUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (pub, ENDPOINT_0));
    msleep (SETTLE_TIME);

    //  confirm that we get following events
    expect_monitor_event (sub_mon, ZMQ_EVENT_CONNECT_DELAYED);
    expect_monitor_event (sub_mon, ZMQ_EVENT_CONNECTED);
    expect_monitor_event (sub_mon, ZMQ_EVENT_HANDSHAKE_SUCCEEDED);

    // ZMQ_EVENT_HANDSHAKE_SUCCEEDED should be last event
    rc = get_monitor_event_with_timeout (sub_mon, &event, &event_address,
                                         SETTLE_TIME);
    assert (rc == -1);

    //  Close sub
    //  TODO why does this use zero_linger?
    test_context_socket_close_zero_linger (sub);
    test_context_socket_close_zero_linger (pub);

    //  Close monitor
    //  TODO why does this use zero_linger?
    test_context_socket_close_zero_linger (sub_mon);
}


#ifdef ZMQ_BUILD_DRAFT_API
// test stopping reconnect on connection refused
void reconnect_stop_on_refused ()
{
    // setup pub socket
    void *pub = test_context_socket (ZMQ_PUB);
    //  Bind pub socket
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (pub, ENDPOINT_0));

    // setup sub socket
    void *sub = test_context_socket (ZMQ_SUB);
    //  Monitor all events on sub
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_socket_monitor (sub, "inproc://monitor-sub", ZMQ_EVENT_ALL));
    //  Create socket for collecting monitor events
    void *sub_mon = test_context_socket (ZMQ_PAIR);
    //  Connect so they'll get events
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sub_mon, "inproc://monitor-sub"));
    // set option to stop reconnecting on error
    int stopReconnectOnError = ZMQ_RECONNECT_STOP_CONN_REFUSED;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (sub, ZMQ_RECONNECT_STOP,
                                               &stopReconnectOnError,
                                               sizeof (stopReconnectOnError)));
    // connect to pub
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sub, ENDPOINT_0));

    //  confirm that we get following events
    expect_monitor_event (sub_mon, ZMQ_EVENT_CONNECT_DELAYED);
    expect_monitor_event (sub_mon, ZMQ_EVENT_CONNECTED);
    expect_monitor_event (sub_mon, ZMQ_EVENT_HANDSHAKE_SUCCEEDED);

    // close the pub socket
    test_context_socket_close_zero_linger (pub);

    //  confirm that we get following events
    expect_monitor_event (sub_mon, ZMQ_EVENT_DISCONNECTED);
    expect_monitor_event (sub_mon, ZMQ_EVENT_CONNECT_RETRIED);
    expect_monitor_event (sub_mon, ZMQ_EVENT_CONNECT_DELAYED);
    expect_monitor_event (sub_mon, ZMQ_EVENT_CLOSED);

    // ZMQ_EVENT_CLOSED should be last event, because of ZMQ_RECONNECT_STOP set above
    int event = 0;
    char *event_address;
    int rc = get_monitor_event_with_timeout (sub_mon, &event, &event_address,
                                             2 * 1000);
    int limit = 0;
    while ((rc != -1) && (++limit < 1000)) {
        print_unexpected_event_stderr (event, rc, 0, -1);
        rc = get_monitor_event_with_timeout (sub_mon, &event, &event_address,
                                             2 * 1000);
    }

    //  Close sub
    //  TODO why does this use zero_linger?
    test_context_socket_close_zero_linger (sub);

    //  Close monitor
    //  TODO why does this use zero_linger?
    test_context_socket_close_zero_linger (sub_mon);
}
#endif

#ifdef ZMQ_BUILD_DRAFT_API
// test stopping reconnect on connection refused
void reconnect_stop_on_handshake_failed ()
{
    char bind_address[MAX_SOCKET_STRING];
    size_t addr_length = sizeof (bind_address);
    void *dummy = test_context_socket (ZMQ_STREAM);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (dummy, "tcp://127.0.0.1:0"));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (dummy, ZMQ_LAST_ENDPOINT, bind_address, &addr_length));

    // setup sub socket
    void *sub = test_context_socket (ZMQ_SUB);
    //  Monitor all events on sub
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_socket_monitor (sub, "inproc://monitor-sub", ZMQ_EVENT_ALL));
    //  Create socket for collecting monitor events
    void *sub_mon = test_context_socket (ZMQ_PAIR);
    //  Connect so they'll get events
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sub_mon, "inproc://monitor-sub"));
    // set handshake interval (i.e., timeout) to a more reasonable value
    int handshakeInterval = 1000;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      sub, ZMQ_HANDSHAKE_IVL, &handshakeInterval, sizeof (handshakeInterval)));
    // set option to stop reconnecting on failed handshake
    int stopReconnectOnError = ZMQ_RECONNECT_STOP_HANDSHAKE_FAILED;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (sub, ZMQ_RECONNECT_STOP,
                                               &stopReconnectOnError,
                                               sizeof (stopReconnectOnError)));
    // connect to dummy stream socket above
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sub, bind_address));

#if 1
    // ZMQ_EVENT_DISCONNECTED should be last event, because of ZMQ_RECONNECT_STOP set above
    expect_monitor_event (sub_mon, ZMQ_EVENT_CONNECT_DELAYED);
    expect_monitor_event (sub_mon, ZMQ_EVENT_CONNECTED);
    expect_monitor_event (sub_mon, ZMQ_EVENT_HANDSHAKE_FAILED_NO_DETAIL);
    expect_monitor_event (sub_mon, ZMQ_EVENT_DISCONNECTED);
#else
    print_events (sub_mon, 2 * 1000, 1000);
#endif

    //  Close sub
    //  TODO why does this use zero_linger?
    test_context_socket_close_zero_linger (sub);
    test_context_socket_close_zero_linger (dummy);

    //  Close monitor
    //  TODO why does this use zero_linger?
    test_context_socket_close_zero_linger (sub_mon);
}
#endif

void setUp ()
{
    setup_test_context ();
}

void tearDown ()
{
    teardown_test_context ();
}

int main (void)
{
    setup_test_environment ();

    UNITY_BEGIN ();

    RUN_TEST (reconnect_default);
    RUN_TEST (reconnect_success);
#ifdef ZMQ_BUILD_DRAFT_API
    RUN_TEST (reconnect_stop_on_refused);
    RUN_TEST (reconnect_stop_on_handshake_failed);
#endif
    return UNITY_END ();
}
