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

SETUP_TEARDOWN_TESTCONTEXT

const int MAX_SENDS = 10000;

enum TestType
{
    BIND_FIRST,
    CONNECT_FIRST
};

void test_defaults ()
{
    // Set up bind socket
    void *bind_socket = test_context_socket (ZMQ_PULL);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (bind_socket, "inproc://a"));

    // Set up connect socket
    void *connect_socket = test_context_socket (ZMQ_PUSH);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (connect_socket, "inproc://a"));

    // Send until we block
    int send_count = 0;
    while (send_count < MAX_SENDS
           && zmq_send (connect_socket, NULL, 0, ZMQ_DONTWAIT) == 0)
        ++send_count;

    msleep (SETTLE_TIME);

    // Now receive all sent messages
    int recv_count = 0;
    while (zmq_recv (bind_socket, NULL, 0, ZMQ_DONTWAIT) == 0)
        ++recv_count;

    TEST_ASSERT_EQUAL_INT (send_count, recv_count);

    // Clean up
    test_context_socket_close (connect_socket);
    test_context_socket_close (bind_socket);

    // Default values are 1000 on send and 1000 one receive, so 2000 total
    TEST_ASSERT_EQUAL_INT (2000, send_count);
}

int count_msg (int send_hwm_, int recv_hwm_, TestType test_type_)
{
    void *bind_socket;
    void *connect_socket;
    if (test_type_ == BIND_FIRST) {
        // Set up bind socket
        bind_socket = test_context_socket (ZMQ_PULL);
        TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
          bind_socket, ZMQ_RCVHWM, &recv_hwm_, sizeof (recv_hwm_)));
        TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (bind_socket, "inproc://a"));

        // Set up connect socket
        connect_socket = test_context_socket (ZMQ_PUSH);
        TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
          connect_socket, ZMQ_SNDHWM, &send_hwm_, sizeof (send_hwm_)));
        TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (connect_socket, "inproc://a"));

        //  we must wait for the connect to succeed here, unfortunately we don't
        //  have monitoring events for inproc, so we just hope SETTLE_TIME suffices
        msleep (SETTLE_TIME);
    } else {
        // Set up connect socket
        connect_socket = test_context_socket (ZMQ_PUSH);
        TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
          connect_socket, ZMQ_SNDHWM, &send_hwm_, sizeof (send_hwm_)));
        TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (connect_socket, "inproc://a"));

        // Set up bind socket
        bind_socket = test_context_socket (ZMQ_PULL);
        TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
          bind_socket, ZMQ_RCVHWM, &recv_hwm_, sizeof (recv_hwm_)));
        TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (bind_socket, "inproc://a"));
    }

    // Send until we block
    int send_count = 0;
    while (send_count < MAX_SENDS
           && zmq_send (connect_socket, NULL, 0, ZMQ_DONTWAIT) == 0)
        ++send_count;

    // Now receive all sent messages
    int recv_count = 0;
    while (zmq_recv (bind_socket, NULL, 0, ZMQ_DONTWAIT) == 0)
        ++recv_count;

    TEST_ASSERT_EQUAL_INT (send_count, recv_count);

    // Now it should be possible to send one more.
    send_string_expect_success (connect_socket, NULL, 0);

    //  Consume the remaining message.
    recv_string_expect_success (bind_socket, NULL, 0);

    // Clean up
    test_context_socket_close (connect_socket);
    test_context_socket_close (bind_socket);

    return send_count;
}

int test_inproc_bind_first (int send_hwm_, int recv_hwm_)
{
    return count_msg (send_hwm_, recv_hwm_, BIND_FIRST);
}

int test_inproc_connect_first (int send_hwm_, int recv_hwm_)
{
    return count_msg (send_hwm_, recv_hwm_, CONNECT_FIRST);
}

int test_inproc_connect_and_close_first (int send_hwm_, int recv_hwm_)
{
    // Set up connect socket
    void *connect_socket = test_context_socket (ZMQ_PUSH);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (connect_socket, ZMQ_SNDHWM,
                                               &send_hwm_, sizeof (send_hwm_)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (connect_socket, "inproc://a"));

    // Send until we block
    int send_count = 0;
    while (send_count < MAX_SENDS
           && zmq_send (connect_socket, NULL, 0, ZMQ_DONTWAIT) == 0)
        ++send_count;

    // Close connect
    test_context_socket_close (connect_socket);

    // Set up bind socket
    void *bind_socket = test_context_socket (ZMQ_PULL);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (bind_socket, ZMQ_RCVHWM, &recv_hwm_, sizeof (recv_hwm_)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (bind_socket, "inproc://a"));

    // Now receive all sent messages
    int recv_count = 0;
    while (zmq_recv (bind_socket, NULL, 0, ZMQ_DONTWAIT) == 0)
        ++recv_count;

    TEST_ASSERT_EQUAL_INT (send_count, recv_count);

    // Clean up
    test_context_socket_close (bind_socket);

    return send_count;
}

int test_inproc_bind_and_close_first (int send_hwm_, int /* recv_hwm */)
{
    // Set up bind socket
    void *bind_socket = test_context_socket (ZMQ_PUSH);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (bind_socket, ZMQ_SNDHWM, &send_hwm_, sizeof (send_hwm_)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (bind_socket, "inproc://a"));

    // Send until we block
    int send_count = 0;
    while (send_count < MAX_SENDS
           && zmq_send (bind_socket, NULL, 0, ZMQ_DONTWAIT) == 0)
        ++send_count;

    // Close bind
    test_context_socket_close (bind_socket);

    /* TODO Can't currently do connect without then wiring up a bind as things hang, this needs top be fixed.
    // Set up connect socket
    void *connect_socket = test_context_socket (ZMQ_PULL);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (connect_socket, ZMQ_RCVHWM, &recv_hwm, sizeof (recv_hwm)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (connect_socket, "inproc://a"));

    // Now receive all sent messages
    int recv_count = 0;
    while (zmq_recv (connect_socket, NULL, 0, ZMQ_DONTWAIT) == 0)
        ++recv_count;

    TEST_ASSERT_EQUAL_INT(send_count, recv_count);
    */

    // Clean up
    //test_context_socket_close (connect_socket);

    return send_count;
}

void test_infinite_both_inproc_bind_first ()
{
    int count = test_inproc_bind_first (0, 0);
    TEST_ASSERT_EQUAL_INT (MAX_SENDS, count);
}

void test_infinite_both_inproc_connect_first ()
{
    int count = test_inproc_connect_first (0, 0);
    TEST_ASSERT_EQUAL_INT (MAX_SENDS, count);
}

void test_infinite_receive_inproc_bind_first ()
{
    int count = test_inproc_bind_first (1, 0);
    TEST_ASSERT_EQUAL_INT (MAX_SENDS, count);
}

void test_infinite_receive_inproc_connect_first ()
{
    int count = test_inproc_connect_first (1, 0);
    TEST_ASSERT_EQUAL_INT (MAX_SENDS, count);
}

void test_infinite_send_inproc_bind_first ()
{
    int count = test_inproc_bind_first (0, 1);
    TEST_ASSERT_EQUAL_INT (MAX_SENDS, count);
}

void test_infinite_send_inproc_connect_first ()
{
    int count = test_inproc_connect_first (0, 1);
    TEST_ASSERT_EQUAL_INT (MAX_SENDS, count);
}

void test_finite_both_bind_first ()
{
    // Send and recv buffers hwm 1, so total that can be queued is 2
    int count = test_inproc_bind_first (1, 1);
    TEST_ASSERT_EQUAL_INT (2, count);
}
void test_finite_both_connect_first ()
{
    // Send and recv buffers hwm 1, so total that can be queued is 2
    int count = test_inproc_connect_first (1, 1);
    TEST_ASSERT_EQUAL_INT (2, count);
}

void test_infinite_recv_connect_and_close_first ()
{
    // Send hwm of 1, send before bind so total that can be queued is 1
    int count = test_inproc_connect_and_close_first (1, 0);
    TEST_ASSERT_EQUAL_INT (1, count);
}

void test_infinite_recv_bind_and_close_first ()
{
    // Send hwm of 1, send from bind side before connect so total that can be queued should be 1,
    // however currently all messages get thrown away before the connect.  BUG?
    /*int count = */ test_inproc_bind_and_close_first (1, 0);
    // TEST_ASSERT_EQUAL_INT (1, count);
}

int main (void)
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_defaults);

    RUN_TEST (test_infinite_both_inproc_bind_first);
    RUN_TEST (test_infinite_both_inproc_connect_first);

    RUN_TEST (test_infinite_receive_inproc_bind_first);
    RUN_TEST (test_infinite_receive_inproc_connect_first);

    RUN_TEST (test_infinite_send_inproc_bind_first);
    RUN_TEST (test_infinite_send_inproc_connect_first);

    RUN_TEST (test_finite_both_bind_first);
    RUN_TEST (test_finite_both_connect_first);

    RUN_TEST (test_infinite_recv_connect_and_close_first);
    RUN_TEST (test_infinite_recv_bind_and_close_first);

    return UNITY_END ();
}
