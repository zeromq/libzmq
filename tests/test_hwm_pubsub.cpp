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
#include "testutil_unity.hpp"

void setUp ()
{
    setup_test_context ();
}

void tearDown ()
{
    teardown_test_context ();
}

// const int MAX_SENDS = 10000;

int test_defaults (int send_hwm, int msgCnt)
{
    // Set up bind socket
    void *pub_socket = test_context_socket (ZMQ_PUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (pub_socket, "inproc://a"));

    // Set up connect socket
    void *sub_socket = test_context_socket (ZMQ_SUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sub_socket, "inproc://a"));

    //set a hwm on publisher
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (pub_socket, ZMQ_SNDHWM, &send_hwm, sizeof (send_hwm)));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sub_socket, ZMQ_SUBSCRIBE, 0, 0));

    // Send until we block
    int send_count = 0;
    while (send_count < msgCnt
           && zmq_send (pub_socket, NULL, 0, ZMQ_DONTWAIT) == 0)
        ++send_count;

    msleep (SETTLE_TIME);

    // Now receive all sent messages
    int recv_count = 0;
    while (0 == zmq_recv (sub_socket, NULL, 0, ZMQ_DONTWAIT)) {
        ++recv_count;
    }

    TEST_ASSERT_EQUAL_INT (send_hwm, recv_count);

    // Clean up
    test_context_socket_close (sub_socket);
    test_context_socket_close (pub_socket);

    return recv_count;
}

int receive (void *socket)
{
    int recv_count = 0;
    // Now receive all sent messages
    while (0 == zmq_recv (socket, NULL, 0, ZMQ_DONTWAIT)) {
        ++recv_count;
    }

    return recv_count;
}


int test_blocking (int send_hwm, int msgCnt)
{
    // Set up bind socket
    void *pub_socket = test_context_socket (ZMQ_PUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (pub_socket, "inproc://a"));

    // Set up connect socket
    void *sub_socket = test_context_socket (ZMQ_SUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sub_socket, "inproc://a"));

    //set a hwm on publisher
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (pub_socket, ZMQ_SNDHWM, &send_hwm, sizeof (send_hwm)));
    int wait = 1;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (pub_socket, ZMQ_XPUB_NODROP, &wait, sizeof (wait)));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sub_socket, ZMQ_SUBSCRIBE, 0, 0));

    // Send until we block
    int send_count = 0;
    int recv_count = 0;
    while (send_count < msgCnt) {
        const int rc = zmq_send (pub_socket, NULL, 0, ZMQ_DONTWAIT);
        if (rc == 0) {
            ++send_count;
        } else if (-1 == rc) {
            TEST_ASSERT_EQUAL_INT (EAGAIN, errno);
            recv_count += receive (sub_socket);
            TEST_ASSERT_EQUAL_INT (send_count, recv_count);
        }
    }

    recv_count += receive (sub_socket);

    // Clean up
    test_context_socket_close (sub_socket);
    test_context_socket_close (pub_socket);

    return recv_count;
}

// hwm should apply to the messages that have already been received
// with hwm 11024: send 9999 msg, receive 9999, send 1100, receive 1100
void test_reset_hwm ()
{
    const int first_count = 9999;
    const int second_count = 1100;
    int hwm = 11024;
    char my_endpoint[MAX_SOCKET_STRING];

    // Set up bind socket
    void *pub_socket = test_context_socket (ZMQ_PUB);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (pub_socket, ZMQ_SNDHWM, &hwm, sizeof (hwm)));
    bind_loopback_ipv4 (pub_socket, my_endpoint, MAX_SOCKET_STRING);

    // Set up connect socket
    void *sub_socket = test_context_socket (ZMQ_SUB);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sub_socket, ZMQ_RCVHWM, &hwm, sizeof (hwm)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sub_socket, my_endpoint));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sub_socket, ZMQ_SUBSCRIBE, 0, 0));

    msleep (SETTLE_TIME);

    // Send messages
    int send_count = 0;
    while (send_count < first_count
           && zmq_send (pub_socket, NULL, 0, ZMQ_DONTWAIT) == 0)
        ++send_count;
    TEST_ASSERT_EQUAL_INT (first_count, send_count);

    msleep (SETTLE_TIME);

    // Now receive all sent messages
    int recv_count = 0;
    while (0 == zmq_recv (sub_socket, NULL, 0, ZMQ_DONTWAIT)) {
        ++recv_count;
    }
    TEST_ASSERT_EQUAL_INT (first_count, recv_count);

    msleep (SETTLE_TIME);

    // Send messages
    send_count = 0;
    while (send_count < second_count
           && zmq_send (pub_socket, NULL, 0, ZMQ_DONTWAIT) == 0)
        ++send_count;
    TEST_ASSERT_EQUAL_INT (second_count, send_count);

    msleep (SETTLE_TIME);

    // Now receive all sent messages
    recv_count = 0;
    while (0 == zmq_recv (sub_socket, NULL, 0, ZMQ_DONTWAIT)) {
        ++recv_count;
    }
    TEST_ASSERT_EQUAL_INT (second_count, recv_count);

    // Clean up
    test_context_socket_close (sub_socket);
    test_context_socket_close (pub_socket);
}

void test_defaults_1000 ()
{
    // send 1000 msg on hwm 1000, receive 1000
    TEST_ASSERT_EQUAL_INT (1000, test_defaults (1000, 1000));
}

void test_blocking_2000 ()
{
    // send 6000 msg on hwm 2000, drops above hwm, only receive hwm
    TEST_ASSERT_EQUAL_INT (6000, test_blocking (2000, 6000));
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_defaults_1000);
    RUN_TEST (test_blocking_2000);
    RUN_TEST (test_reset_hwm);
    return UNITY_END ();
}
