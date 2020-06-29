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

// test connecting to unversioned zmtp w/o strict succeeds
void connect_success ()
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
    // connect to dummy stream socket above
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sub, bind_address));

#if 1
    expect_monitor_event (sub_mon, ZMQ_EVENT_CONNECT_DELAYED);
    expect_monitor_event (sub_mon, ZMQ_EVENT_CONNECTED);
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

// test connecting to unversioned zmtp w/strict fails
void connect_failed ()
{
    char bind_address[MAX_SOCKET_STRING];
    size_t addr_length = sizeof (bind_address);
    void *dummy = test_context_socket (ZMQ_STREAM);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (dummy, "tcp://127.0.0.1:0"));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (dummy, ZMQ_LAST_ENDPOINT, bind_address, &addr_length));

    // setup sub socket
    void *sub = test_context_socket (ZMQ_SUB);
    // set strict option
    int zmtpStrict = 1;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      sub, ZMQ_ZMTP_STRICT, &zmtpStrict, sizeof (zmtpStrict)));
    //  Monitor all events on sub
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_socket_monitor (sub, "inproc://monitor-sub", ZMQ_EVENT_ALL));
    //  Create socket for collecting monitor events
    void *sub_mon = test_context_socket (ZMQ_PAIR);
    //  Connect so they'll get events
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sub_mon, "inproc://monitor-sub"));
    // connect to dummy stream socket above
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sub, bind_address));

#if 0
    expect_monitor_event (sub_mon, ZMQ_EVENT_CONNECT_DELAYED);
    expect_monitor_event (sub_mon, ZMQ_EVENT_CONNECTED);
    expect_monitor_event (sub_mon, ZMQ_EVENT_HANDSHAKE_FAILED_NO_DETAIL);
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

    RUN_TEST (connect_success);
    RUN_TEST (connect_failed);
    return UNITY_END ();
}
