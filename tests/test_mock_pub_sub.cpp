/*
    Copyright (c) 2018 Contributors as noted in the AUTHORS file

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "testutil.hpp"
#include "testutil_unity.hpp"
#if defined(ZMQ_HAVE_WINDOWS)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdexcept>
#define close closesocket
typedef SOCKET raw_socket;
#else
#include <arpa/inet.h>
#include <unistd.h>
typedef int raw_socket;
#endif

#include <stdlib.h>
#include <string.h>

SETUP_TEARDOWN_TESTCONTEXT

//  Read one event off the monitor socket; return value and address
//  by reference, if not null, and event number by value. Returns -1
//  in case of error.

static int get_monitor_event (void *monitor_)
{
    for (int i = 0; i < 2; i++) {
        //  First frame in message contains event number and value
        zmq_msg_t msg;
        TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init (&msg));
        if (zmq_msg_recv (&msg, monitor_, ZMQ_DONTWAIT) == -1) {
            msleep (SETTLE_TIME);
            continue; //  Interrupted, presumably
        }
        TEST_ASSERT_TRUE (zmq_msg_more (&msg));

        uint8_t *data = (uint8_t *) zmq_msg_data (&msg);
        uint16_t event = *(uint16_t *) (data);

        //  Second frame in message contains event address
        TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init (&msg));
        if (zmq_msg_recv (&msg, monitor_, 0) == -1) {
            return -1; //  Interrupted, presumably
        }
        TEST_ASSERT_FALSE (zmq_msg_more (&msg));

        return event;
    }
    return -1;
}

static void recv_with_retry (raw_socket fd_, char *buffer_, int bytes_)
{
    int received = 0;
    while (true) {
        int rc = TEST_ASSERT_SUCCESS_RAW_ERRNO (
          recv (fd_, buffer_ + received, bytes_ - received, 0));
        TEST_ASSERT_GREATER_THAN_INT (0, rc);
        received += rc;
        TEST_ASSERT_LESS_OR_EQUAL_INT (bytes_, received);
        if (received == bytes_)
            break;
    }
}

static void mock_handshake (raw_socket fd_)
{
    const uint8_t zmtp_greeting[33] = {0xff, 0, 0, 0,   0,   0,   0,   0, 0,
                                       0x7f, 3, 0, 'N', 'U', 'L', 'L', 0};
    char buffer[128];
    memset (buffer, 0, sizeof (buffer));
    memcpy (buffer, zmtp_greeting, sizeof (zmtp_greeting));

    int rc = TEST_ASSERT_SUCCESS_RAW_ERRNO (send (fd_, buffer, 64, 0));
    TEST_ASSERT_EQUAL_INT (64, rc);

    recv_with_retry (fd_, buffer, 64);

    const uint8_t zmtp_ready[27] = {
      4,   25,  5,   'R', 'E', 'A', 'D', 'Y', 11, 'S', 'o', 'c', 'k', 'e',
      't', '-', 'T', 'y', 'p', 'e', 0,   0,   0,  3,   'S', 'U', 'B'};

    memset (buffer, 0, sizeof (buffer));
    memcpy (buffer, zmtp_ready, 27);
    rc = TEST_ASSERT_SUCCESS_RAW_ERRNO (send (fd_, buffer, 27, 0));
    TEST_ASSERT_EQUAL_INT (27, rc);

    //  greeting - XPUB so one extra byte
    recv_with_retry (fd_, buffer, 28);
}

static void prep_server_socket (void **server_out_,
                                void **mon_out_,
                                char *endpoint_,
                                size_t ep_length_)
{
    //  We'll be using this socket in raw mode
    void *server = test_context_socket (ZMQ_XPUB);

    int value = 0;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (server, ZMQ_LINGER, &value, sizeof (value)));

    bind_loopback_ipv4 (server, endpoint_, ep_length_);

    //  Create and connect a socket for collecting monitor events on xpub
    void *server_mon = test_context_socket (ZMQ_PAIR);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_socket_monitor (
      server, "inproc://monitor-dealer",
      ZMQ_EVENT_CONNECTED | ZMQ_EVENT_DISCONNECTED | ZMQ_EVENT_ACCEPTED));

    //  Connect to the inproc endpoint so we'll get events
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_connect (server_mon, "inproc://monitor-dealer"));

    *server_out_ = server;
    *mon_out_ = server_mon;
}

static void test_mock_sub (bool sub_command)
{
    int rc;
    char my_endpoint[MAX_SOCKET_STRING];

    void *server, *server_mon;
    prep_server_socket (&server, &server_mon, my_endpoint, MAX_SOCKET_STRING);

    struct sockaddr_in ip4addr;
    raw_socket s;

    ip4addr.sin_family = AF_INET;
    ip4addr.sin_port = htons (atoi (strrchr (my_endpoint, ':') + 1));
#if defined(ZMQ_HAVE_WINDOWS) && (_WIN32_WINNT < 0x0600)
    ip4addr.sin_addr.s_addr = inet_addr ("127.0.0.1");
#else
    inet_pton (AF_INET, "127.0.0.1", &ip4addr.sin_addr);
#endif

    s = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
    rc = TEST_ASSERT_SUCCESS_RAW_ERRNO (
      connect (s, (struct sockaddr *) &ip4addr, sizeof ip4addr));
    TEST_ASSERT_GREATER_THAN_INT (-1, rc);

    // Mock a ZMTP 3 client so we can forcibly try sub commands
    mock_handshake (s);

    // By now everything should report as connected
    rc = get_monitor_event (server_mon);
    TEST_ASSERT_EQUAL_INT (ZMQ_EVENT_ACCEPTED, rc);

    if (sub_command) {
        const uint8_t sub[13] = {4,   11,  9,   'S', 'U', 'B', 'S',
                                 'C', 'R', 'I', 'B', 'E', 'A'};
        rc =
          TEST_ASSERT_SUCCESS_RAW_ERRNO (send (s, (const char *) sub, 13, 0));
        TEST_ASSERT_EQUAL_INT (13, rc);
    } else {
        const uint8_t sub[4] = {0, 2, 1, 'A'};
        rc = TEST_ASSERT_SUCCESS_RAW_ERRNO (send (s, (const char *) sub, 4, 0));
        TEST_ASSERT_EQUAL_INT (4, rc);
    }

    char buffer[16];
    memset (buffer, 0, sizeof (buffer));
    rc = zmq_recv (server, buffer, 2, 0);
    TEST_ASSERT_EQUAL_INT (2, rc);
    TEST_ASSERT_EQUAL_INT (0, memcmp (buffer, "\1A", 2));

    rc = zmq_send (server, "ALOL", 4, 0);
    TEST_ASSERT_EQUAL_INT (4, rc);

    memset (buffer, 0, sizeof (buffer));
    recv_with_retry (s, buffer, 6);
    TEST_ASSERT_EQUAL_INT (0, memcmp (buffer, "\0\4ALOL", 6));

    close (s);

    test_context_socket_close (server);
    test_context_socket_close (server_mon);
}

void test_mock_sub_command ()
{
    test_mock_sub (true);
}

void test_mock_sub_legacy ()
{
    test_mock_sub (false);
}

int main (void)
{
    setup_test_environment ();

    UNITY_BEGIN ();

    RUN_TEST (test_mock_sub_command);
    RUN_TEST (test_mock_sub_legacy);

    return UNITY_END ();
}
