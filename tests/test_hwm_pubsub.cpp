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

#include <string.h>

// NOTE: on OSX the endpoint returned by ZMQ_LAST_ENDPOINT may be quite long,
//       ensure we have extra space for that:
#define SOCKET_STRING_LEN (MAX_SOCKET_STRING * 4)

SETUP_TEARDOWN_TESTCONTEXT

int test_defaults (int send_hwm_, int msg_cnt_, const char *endpoint)
{
    char pub_endpoint[SOCKET_STRING_LEN];

    // Set up and bind XPUB socket
    void *pub_socket = test_context_socket (ZMQ_XPUB);
    test_bind (pub_socket, endpoint, pub_endpoint, sizeof pub_endpoint);

    // Set up and connect SUB socket
    void *sub_socket = test_context_socket (ZMQ_SUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sub_socket, pub_endpoint));

    //set a hwm on publisher
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (pub_socket, ZMQ_SNDHWM, &send_hwm_, sizeof (send_hwm_)));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sub_socket, ZMQ_SUBSCRIBE, 0, 0));

    // Wait before starting TX operations till 1 subscriber has subscribed
    // (in this test there's 1 subscriber only)
    const char subscription_to_all_topics[] = {1, 0};
    recv_string_expect_success (pub_socket, subscription_to_all_topics, 0);

    // Send until we reach "mute" state
    int send_count = 0;
    while (send_count < msg_cnt_
           && zmq_send (pub_socket, "test message", 13, ZMQ_DONTWAIT) == 13)
        ++send_count;

    TEST_ASSERT_EQUAL_INT (send_hwm_, send_count);
    msleep (SETTLE_TIME);

    // Now receive all sent messages
    int recv_count = 0;
    char dummybuff[64];
    while (13 == zmq_recv (sub_socket, &dummybuff, 64, ZMQ_DONTWAIT)) {
        ++recv_count;
    }

    TEST_ASSERT_EQUAL_INT (send_hwm_, recv_count);

    // Clean up
    test_context_socket_close (sub_socket);
    test_context_socket_close (pub_socket);

    return recv_count;
}

int receive (void *socket_, int *is_termination)
{
    int recv_count = 0;
    *is_termination = 0;

    // Now receive all sent messages
    char buffer[255];
    int len;
    while ((len = zmq_recv (socket_, buffer, sizeof (buffer), 0)) >= 0) {
        ++recv_count;

        if (len == 3 && strncmp (buffer, "end", len) == 0) {
            *is_termination = 1;
            return recv_count;
        }
    }

    return recv_count;
}

int test_blocking (int send_hwm_, int msg_cnt_, const char *endpoint)
{
    char pub_endpoint[SOCKET_STRING_LEN];

    // Set up bind socket
    void *pub_socket = test_context_socket (ZMQ_XPUB);
    test_bind (pub_socket, endpoint, pub_endpoint, sizeof pub_endpoint);

    // Set up connect socket
    void *sub_socket = test_context_socket (ZMQ_SUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sub_socket, pub_endpoint));

    //set a hwm on publisher
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (pub_socket, ZMQ_SNDHWM, &send_hwm_, sizeof (send_hwm_)));
    int wait = 1;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (pub_socket, ZMQ_XPUB_NODROP, &wait, sizeof (wait)));
    int timeout_ms = 10;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      sub_socket, ZMQ_RCVTIMEO, &timeout_ms, sizeof (timeout_ms)));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sub_socket, ZMQ_SUBSCRIBE, 0, 0));

    // Wait before starting TX operations till 1 subscriber has subscribed
    // (in this test there's 1 subscriber only)
    const uint8_t subscription_to_all_topics[] = {1};
    recv_array_expect_success (pub_socket, subscription_to_all_topics, 0);

    // Send until we block
    int send_count = 0;
    int recv_count = 0;
    int blocked_count = 0;
    int is_termination = 0;
    while (send_count < msg_cnt_) {
        const int rc = zmq_send (pub_socket, NULL, 0, ZMQ_DONTWAIT);
        if (rc == 0) {
            ++send_count;
        } else if (-1 == rc) {
            // if the PUB socket blocks due to HWM, errno should be EAGAIN:
            blocked_count++;
            TEST_ASSERT_FAILURE_ERRNO (EAGAIN, -1);
            recv_count += receive (sub_socket, &is_termination);
        }
    }

    // if send_hwm_ < msg_cnt_, we should block at least once:
    char counts_string[128];
    snprintf (counts_string, sizeof counts_string - 1,
              "sent = %i, received = %i", send_count, recv_count);
    TEST_ASSERT_GREATER_THAN_INT_MESSAGE (0, blocked_count, counts_string);

    // dequeue SUB socket again, to make sure XPUB has space to send the termination message
    recv_count += receive (sub_socket, &is_termination);

    // send termination message
    send_string_expect_success (pub_socket, "end", 0);

    // now block on the SUB side till we get the termination message
    while (is_termination == 0)
        recv_count += receive (sub_socket, &is_termination);

    // remove termination message from the count:
    recv_count--;

    TEST_ASSERT_EQUAL_INT (send_count, recv_count);

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
    char my_endpoint[SOCKET_STRING_LEN];

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

void test_defaults_large (const char *bind_endpoint_)
{
    // send 1000 msg on hwm 1000, receive 1000
    TEST_ASSERT_EQUAL_INT (1000, test_defaults (1000, 1000, bind_endpoint_));
}

void test_defaults_small (const char *bind_endpoint_)
{
    // send 1000 msg on hwm 100, receive 100
    TEST_ASSERT_EQUAL_INT (100, test_defaults (100, 100, bind_endpoint_));
}

void test_blocking (const char *bind_endpoint_)
{
    // send 6000 msg on hwm 2000, drops above hwm, only receive hwm:
    TEST_ASSERT_EQUAL_INT (6000, test_blocking (2000, 6000, bind_endpoint_));
}

#define DEFINE_REGULAR_TEST_CASES(name, bind_endpoint)                         \
    void test_defaults_large_##name ()                                         \
    {                                                                          \
        test_defaults_large (bind_endpoint);                                   \
    }                                                                          \
                                                                               \
    void test_defaults_small_##name ()                                         \
    {                                                                          \
        test_defaults_small (bind_endpoint);                                   \
    }                                                                          \
                                                                               \
    void test_blocking_##name () { test_blocking (bind_endpoint); }

#define RUN_REGULAR_TEST_CASES(name)                                           \
    RUN_TEST (test_defaults_large_##name);                                     \
    RUN_TEST (test_defaults_small_##name);                                     \
    RUN_TEST (test_blocking_##name)

DEFINE_REGULAR_TEST_CASES (tcp, "tcp://127.0.0.1:*")
DEFINE_REGULAR_TEST_CASES (inproc, "inproc://a")

#if !defined(ZMQ_HAVE_WINDOWS) && !defined(ZMQ_HAVE_GNU)
DEFINE_REGULAR_TEST_CASES (ipc, "ipc://*")
#endif

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();

    RUN_REGULAR_TEST_CASES (tcp);
    RUN_REGULAR_TEST_CASES (inproc);

#if !defined(ZMQ_HAVE_WINDOWS) && !defined(ZMQ_HAVE_GNU)
    RUN_REGULAR_TEST_CASES (ipc);
#endif
    RUN_TEST (test_reset_hwm);
    return UNITY_END ();
}
