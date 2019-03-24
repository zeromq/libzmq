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
#include "testutil_unity.hpp"
#include "testutil_security.hpp"

SETUP_TEARDOWN_TESTCONTEXT

void test_send_one_connected_one_unconnected ()
{
    int val;
    // TEST 1.
    // First we're going to attempt to send messages to two
    // pipes, one connected, the other not. We should see
    // the PUSH load balancing to both pipes, and hence half
    // of the messages getting queued, as connect() creates a
    // pipe immediately.

    void *to = test_context_socket (ZMQ_PULL);
    int timeout = 5000;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (to, ZMQ_LINGER, &timeout, sizeof (timeout)));

    // Bind the one valid receiver
    val = 0;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (to, ZMQ_LINGER, &val, sizeof (val)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (to, "tipc://{6555,0,0}"));

    // Create a socket pushing to two endpoints - only 1 message should arrive.
    void *from = test_context_socket (ZMQ_PUSH);

    val = 0;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (from, ZMQ_LINGER, &val, sizeof (val)));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (from, ZMQ_LINGER, &timeout, sizeof (timeout)));
    // This pipe will not connect
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (from, "tipc://{5556,0}@0.0.0"));
    // This pipe will
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (from, "tipc://{6555,0}@0.0.0"));

    // We send 10 messages, 5 should just get stuck in the queue
    // for the not-yet-connected pipe
    const int send_count = 10;
    for (int i = 0; i < send_count; ++i) {
        send_string_expect_success (from, "Hello", 0);
    }

    // We now consume from the connected pipe
    // - we should see just 5
    timeout = SETTLE_TIME;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (to, ZMQ_RCVTIMEO, &timeout, sizeof (int)));

    int seen = 0;
    while (true) {
        char buffer[16];
        int rc = zmq_recv (to, &buffer, sizeof (buffer), 0);
        if (rc == -1) {
            TEST_ASSERT_EQUAL_INT (EAGAIN, zmq_errno ());
            break; //  Break when we didn't get a message
        }
        seen++;
    }
    TEST_ASSERT_EQUAL_INT (send_count / 2, seen);

    test_context_socket_close (from);
    test_context_socket_close (to);
}

void test_send_one_connected_one_unconnected_with_delay ()
{
    int val;

    // TEST 2
    // This time we will do the same thing, connect two pipes,
    // one of which will succeed in connecting to a bound
    // receiver, the other of which will fail. However, we will
    // also set the delay attach on connect flag, which should
    // cause the pipe attachment to be delayed until the connection
    // succeeds.

    // Bind the valid socket
    void *to = test_context_socket (ZMQ_PULL);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (to, "tipc://{5560,0,0}"));
    int timeout = 5000;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (to, ZMQ_LINGER, &timeout, sizeof (timeout)));

    val = 0;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (to, ZMQ_LINGER, &val, sizeof (val)));

    // Create a socket pushing to two endpoints - all messages should arrive.
    void *from = test_context_socket (ZMQ_PUSH);

    val = 0;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (from, ZMQ_LINGER, &val, sizeof (val)));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (from, ZMQ_LINGER, &timeout, sizeof (timeout)));

    // Set the key flag
    val = 1;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (from, ZMQ_DELAY_ATTACH_ON_CONNECT, &val, sizeof (val)));

    // Connect to the invalid socket
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (from, "tipc://{5561,0}@0.0.0"));
    // Connect to the valid socket
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (from, "tipc://{5560,0}@0.0.0"));

    // Send 10 messages, all should be routed to the connected pipe
    const int send_count = 10;
    for (int i = 0; i < send_count; ++i) {
        send_string_expect_success (from, "Hello", 0);
    }
    timeout = SETTLE_TIME;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (to, ZMQ_RCVTIMEO, &timeout, sizeof (int)));

    int seen = 0;
    while (true) {
        char buffer[16];
        int rc = zmq_recv (to, &buffer, sizeof (buffer), 0);
        if (rc == -1) {
            TEST_ASSERT_EQUAL_INT (EAGAIN, zmq_errno ());
            break; //  Break when we didn't get a message
        }
        seen++;
    }
    TEST_ASSERT_EQUAL_INT (send_count, seen);

    test_context_socket_close (from);
    test_context_socket_close (to);
}

void test_send_disconnected_with_delay ()
{
    // TEST 3
    // This time we want to validate that the same blocking behaviour
    // occurs with an existing connection that is broken. We will send
    // messages to a connected pipe, disconnect and verify the messages
    // block. Then we reconnect and verify messages flow again.
    void *backend = test_context_socket (ZMQ_DEALER);
    void *frontend = test_context_socket (ZMQ_DEALER);
    void *monitor = test_context_socket (ZMQ_PAIR);
    int rc;
    int zero = 0;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (backend, ZMQ_LINGER, &zero, sizeof (zero)));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (frontend, ZMQ_LINGER, &zero, sizeof (zero)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_socket_monitor (frontend, "inproc://monitor",
                                                   ZMQ_EVENT_DISCONNECTED));
    int timeout = 5000;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (backend, ZMQ_LINGER, &timeout, sizeof (timeout)));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (frontend, ZMQ_LINGER, &timeout, sizeof (timeout)));

    //  Frontend connects to backend using DELAY_ATTACH_ON_CONNECT
    int on = 1;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (frontend, ZMQ_DELAY_ATTACH_ON_CONNECT, &on, sizeof (on)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (backend, "tipc://{5560,0,0}"));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (monitor, "inproc://monitor"));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (frontend, "tipc://{5560,0}@0.0.0"));

    //  Ping backend to frontend so we know when the connection is up
    send_string_expect_success (backend, "Hello", 0);
    recv_string_expect_success (frontend, "Hello", 0);

    // Send message from frontend to backend
    send_string_expect_success (frontend, "Hello", ZMQ_DONTWAIT);

    test_context_socket_close (backend);

    // Wait for disconnect to happen
    expect_monitor_event (monitor, ZMQ_EVENT_DISCONNECTED);

    // Send a message, might succeed depending on scheduling of the I/O thread
    do {
        rc = zmq_send (frontend, "Hello", 5, ZMQ_DONTWAIT);
        TEST_ASSERT_TRUE (rc == 5 || (rc == -1 && zmq_errno () == EAGAIN));
    } while (rc == 5);

    //  Recreate backend socket
    backend = test_context_socket (ZMQ_DEALER);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (backend, ZMQ_LINGER, &zero, sizeof (zero)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (backend, "tipc://{5560,0,0}"));

    //  Ping backend to frontend so we know when the connection is up
    send_string_expect_success (backend, "Hello", 0);
    recv_string_expect_success (frontend, "Hello", 0);

    // After the reconnect, should succeed
    send_string_expect_success (frontend, "Hello", ZMQ_DONTWAIT);

    test_context_socket_close (monitor);
    test_context_socket_close (backend);
    test_context_socket_close (frontend);
}

int main (void)
{
    if (!is_tipc_available ()) {
        printf ("TIPC environment unavailable, skipping test\n");
        return 77;
    }

    UNITY_BEGIN ();
    RUN_TEST (test_send_one_connected_one_unconnected);
    RUN_TEST (test_send_one_connected_one_unconnected_with_delay);
    RUN_TEST (test_send_disconnected_with_delay);
    return UNITY_END ();
}
