/*
    Copyright (c) 2007-2017 Contributors as noted in the AUTHORS file

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

#include <limits.h>
#include <stdlib.h>
#include <string.h>

// TODO remove this here, either ensure that UINT16_MAX is always properly
// defined or handle this at a more central location
#ifndef UINT16_MAX
#define UINT16_MAX 65535
#endif

#include "testutil_unity.hpp"

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

static void mock_handshake (raw_socket fd_, int mock_ping_)
{
    const uint8_t zmtp_greeting[33] = {0xff, 0, 0, 0,   0,   0,   0,   0, 0,
                                       0x7f, 3, 0, 'N', 'U', 'L', 'L', 0};
    char buffer[128];
    memset (buffer, 0, sizeof (buffer));
    memcpy (buffer, zmtp_greeting, sizeof (zmtp_greeting));

    int rc = TEST_ASSERT_SUCCESS_RAW_ERRNO (send (fd_, buffer, 64, 0));
    TEST_ASSERT_EQUAL_INT (64, rc);

    recv_with_retry (fd_, buffer, 64);

    const uint8_t zmtp_ready[43] = {
      4,   41,  5,   'R', 'E', 'A', 'D', 'Y', 11,  'S', 'o', 'c', 'k', 'e', 't',
      '-', 'T', 'y', 'p', 'e', 0,   0,   0,   6,   'D', 'E', 'A', 'L', 'E', 'R',
      8,   'I', 'd', 'e', 'n', 't', 'i', 't', 'y', 0,   0,   0,   0};

    memset (buffer, 0, sizeof (buffer));
    memcpy (buffer, zmtp_ready, 43);
    rc = TEST_ASSERT_SUCCESS_RAW_ERRNO (send (fd_, buffer, 43, 0));
    TEST_ASSERT_EQUAL_INT (43, rc);

    //  greeting
    recv_with_retry (fd_, buffer, 43);

    if (mock_ping_) {
        //  test PING context - should be replicated in the PONG
        //  to avoid timeouts, do a bulk send
        const uint8_t zmtp_ping[12] = {4,   10, 4, 'P', 'I', 'N',
                                       'G', 0,  0, 'L', 'O', 'L'};
        uint8_t zmtp_pong[10] = {4, 8, 4, 'P', 'O', 'N', 'G', 'L', 'O', 'L'};
        memset (buffer, 0, sizeof (buffer));
        memcpy (buffer, zmtp_ping, 12);
        rc = TEST_ASSERT_SUCCESS_RAW_ERRNO (send (fd_, buffer, 12, 0));
        TEST_ASSERT_EQUAL_INT (12, rc);

        //  test a larger body that won't fit in a small message and should get
        //  truncated
        memset (buffer, 'z', sizeof (buffer));
        memcpy (buffer, zmtp_ping, 12);
        buffer[1] = 65;
        rc = TEST_ASSERT_SUCCESS_RAW_ERRNO (send (fd_, buffer, 67, 0));
        TEST_ASSERT_EQUAL_INT (67, rc);

        //  small pong
        recv_with_retry (fd_, buffer, 10);
        TEST_ASSERT_EQUAL_INT (0, memcmp (zmtp_pong, buffer, 10));
        //  large pong
        recv_with_retry (fd_, buffer, 23);
        uint8_t zmtp_pooong[65] = {4, 21, 4, 'P', 'O', 'N', 'G', 'L', 'O', 'L'};
        memset (zmtp_pooong + 10, 'z', 55);
        TEST_ASSERT_EQUAL_INT (0, memcmp (zmtp_pooong, buffer, 23));
    }
}

static void setup_curve (void *socket_, int is_server_)
{
    const char *secret_key;
    const char *public_key;
    const char *server_key;

    if (is_server_) {
        secret_key = "JTKVSB%%)wK0E.X)V>+}o?pNmC{O&4W4b!Ni{Lh6";
        public_key = "rq:rM>}U?@Lns47E1%kR.o@n%FcmmsL/@{H8]yf7";
        server_key = NULL;
    } else {
        secret_key = "D:)Q[IlAW!ahhC2ac:9*A}h:p?([4%wOTJ%JR%cs";
        public_key = "Yne@$w-vo<fVvi]a<NY6T1ed:M$fCG*[IaLV{hID";
        server_key = "rq:rM>}U?@Lns47E1%kR.o@n%FcmmsL/@{H8]yf7";
    }

    zmq_setsockopt (socket_, ZMQ_CURVE_SECRETKEY, secret_key,
                    strlen (secret_key));
    zmq_setsockopt (socket_, ZMQ_CURVE_PUBLICKEY, public_key,
                    strlen (public_key));
    if (is_server_)
        zmq_setsockopt (socket_, ZMQ_CURVE_SERVER, &is_server_,
                        sizeof (is_server_));
    else
        zmq_setsockopt (socket_, ZMQ_CURVE_SERVERKEY, server_key,
                        strlen (server_key));
}

static void prep_server_socket (int set_heartbeats_,
                                int is_curve_,
                                void **server_out_,
                                void **mon_out_,
                                char *endpoint_,
                                size_t ep_length_,
                                int socket_type_)
{
    //  We'll be using this socket in raw mode
    void *server = test_context_socket (socket_type_);

    int value = 0;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (server, ZMQ_LINGER, &value, sizeof (value)));

    if (set_heartbeats_) {
        value = 50;
        TEST_ASSERT_SUCCESS_ERRNO (
          zmq_setsockopt (server, ZMQ_HEARTBEAT_IVL, &value, sizeof (value)));
    }

    if (is_curve_)
        setup_curve (server, 1);

    bind_loopback_ipv4 (server, endpoint_, ep_length_);

    //  Create and connect a socket for collecting monitor events on dealer
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

// This checks for a broken TCP connection (or, in this case a stuck one
// where the peer never responds to PINGS). There should be an accepted event
// then a disconnect event.
static void test_heartbeat_timeout (int server_type_, int mock_ping_)
{
    int rc;
    char my_endpoint[MAX_SOCKET_STRING];

    void *server, *server_mon;
    prep_server_socket (!mock_ping_, 0, &server, &server_mon, my_endpoint,
                        MAX_SOCKET_STRING, server_type_);

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

    // Mock a ZMTP 3 client so we can forcibly time out a connection
    mock_handshake (s, mock_ping_);

    // By now everything should report as connected
    rc = get_monitor_event (server_mon);
    TEST_ASSERT_EQUAL_INT (ZMQ_EVENT_ACCEPTED, rc);

    if (!mock_ping_) {
        // We should have been disconnected
        rc = get_monitor_event (server_mon);
        TEST_ASSERT_EQUAL_INT (ZMQ_EVENT_DISCONNECTED, rc);
    }

    close (s);

    test_context_socket_close (server);
    test_context_socket_close (server_mon);
}

// This checks that peers respect the TTL value in ping messages
// We set up a mock ZMTP 3 client and send a ping message with a TLL
// to a server that is not doing any heartbeating. Then we sleep,
// if the server disconnects the client, then we know the TTL did
// its thing correctly.
static void test_heartbeat_ttl (int client_type_, int server_type_)
{
    int rc, value;
    char my_endpoint[MAX_SOCKET_STRING];

    void *server, *server_mon, *client;
    prep_server_socket (0, 0, &server, &server_mon, my_endpoint,
                        MAX_SOCKET_STRING, server_type_);

    client = test_context_socket (client_type_);

    // Set the heartbeat TTL to 0.1 seconds
    value = 100;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (client, ZMQ_HEARTBEAT_TTL, &value, sizeof (value)));

    // Set the heartbeat interval to much longer than the TTL so that
    // the socket times out oon the remote side.
    value = 250;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (client, ZMQ_HEARTBEAT_IVL, &value, sizeof (value)));

    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (client, my_endpoint));

    // By now everything should report as connected
    rc = get_monitor_event (server_mon);
    TEST_ASSERT_EQUAL_INT (ZMQ_EVENT_ACCEPTED, rc);

    msleep (SETTLE_TIME);

    // We should have been disconnected
    rc = get_monitor_event (server_mon);
    TEST_ASSERT_EQUAL_INT (ZMQ_EVENT_DISCONNECTED, rc);

    test_context_socket_close (server);
    test_context_socket_close (server_mon);
    test_context_socket_close (client);
}

// This checks for normal operation - that is pings and pongs being
// exchanged normally. There should be an accepted event on the server,
// and then no event afterwards.
static void
test_heartbeat_notimeout (int is_curve_, int client_type_, int server_type_)
{
    int rc;
    char my_endpoint[MAX_SOCKET_STRING];

    void *server, *server_mon;
    prep_server_socket (1, is_curve_, &server, &server_mon, my_endpoint,
                        MAX_SOCKET_STRING, server_type_);

    void *client = test_context_socket (client_type_);
    if (is_curve_)
        setup_curve (client, 0);
    rc = zmq_connect (client, my_endpoint);

    // Give it a sec to connect and handshake
    msleep (SETTLE_TIME);

    // By now everything should report as connected
    rc = get_monitor_event (server_mon);
    TEST_ASSERT_EQUAL_INT (ZMQ_EVENT_ACCEPTED, rc);

    // We should still be connected because pings and pongs are happenin'
    TEST_ASSERT_EQUAL_INT (-1, get_monitor_event (server_mon));

    test_context_socket_close (client);
    test_context_socket_close (server);
    test_context_socket_close (server_mon);
}

void test_heartbeat_timeout_router ()
{
    test_heartbeat_timeout (ZMQ_ROUTER, 0);
}

void test_heartbeat_timeout_router_mock_ping ()
{
    test_heartbeat_timeout (ZMQ_ROUTER, 1);
}

#define DEFINE_TESTS(first, second, first_define, second_define)               \
    void test_heartbeat_ttl_##first##_##second ()                              \
    {                                                                          \
        test_heartbeat_ttl (first_define, second_define);                      \
    }                                                                          \
    void test_heartbeat_notimeout_##first##_##second ()                        \
    {                                                                          \
        test_heartbeat_notimeout (0, first_define, second_define);             \
    }                                                                          \
    void test_heartbeat_notimeout_##first##_##second##_with_curve ()           \
    {                                                                          \
        test_heartbeat_notimeout (1, first_define, second_define);             \
    }

DEFINE_TESTS (dealer, router, ZMQ_DEALER, ZMQ_ROUTER)
DEFINE_TESTS (req, rep, ZMQ_REQ, ZMQ_REP)
DEFINE_TESTS (pull, push, ZMQ_PULL, ZMQ_PUSH)
DEFINE_TESTS (sub, pub, ZMQ_SUB, ZMQ_PUB)
DEFINE_TESTS (pair, pair, ZMQ_PAIR, ZMQ_PAIR)

#ifdef ZMQ_BUILD_DRAFT_API
DEFINE_TESTS (gather, scatter, ZMQ_GATHER, ZMQ_SCATTER)
DEFINE_TESTS (client, server, ZMQ_CLIENT, ZMQ_SERVER)
#endif

const int deciseconds_per_millisecond = 100;
const int heartbeat_ttl_max =
  (UINT16_MAX + 1) * deciseconds_per_millisecond - 1;

void test_setsockopt_heartbeat_success (const int value_)
{
    void *const socket = test_context_socket (ZMQ_PAIR);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (socket, ZMQ_HEARTBEAT_TTL, &value_, sizeof (value_)));

    int value_read;
    size_t value_read_size = sizeof (value_read);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_getsockopt (socket, ZMQ_HEARTBEAT_TTL,
                                               &value_read, &value_read_size));

    TEST_ASSERT_EQUAL_INT (value_ - value_ % deciseconds_per_millisecond,
                           value_read);

    test_context_socket_close (socket);
}

void test_setsockopt_heartbeat_ttl_max ()
{
    test_setsockopt_heartbeat_success (heartbeat_ttl_max);
}

void test_setsockopt_heartbeat_ttl_more_than_max_fails ()
{
    void *const socket = test_context_socket (ZMQ_PAIR);
    const int value = heartbeat_ttl_max + 1;
    TEST_ASSERT_FAILURE_ERRNO (
      EINVAL,
      zmq_setsockopt (socket, ZMQ_HEARTBEAT_TTL, &value, sizeof (value)));

    test_context_socket_close (socket);
}

void test_setsockopt_heartbeat_ttl_near_zero ()
{
    test_setsockopt_heartbeat_success (deciseconds_per_millisecond - 1);
}

int main (void)
{
    setup_test_environment ();

    UNITY_BEGIN ();

    RUN_TEST (test_heartbeat_timeout_router);
    RUN_TEST (test_heartbeat_timeout_router_mock_ping);

    RUN_TEST (test_heartbeat_ttl_dealer_router);
    RUN_TEST (test_heartbeat_ttl_req_rep);
    RUN_TEST (test_heartbeat_ttl_pull_push);
    RUN_TEST (test_heartbeat_ttl_sub_pub);
    RUN_TEST (test_heartbeat_ttl_pair_pair);

    RUN_TEST (test_setsockopt_heartbeat_ttl_max);
    RUN_TEST (test_setsockopt_heartbeat_ttl_more_than_max_fails);
    RUN_TEST (test_setsockopt_heartbeat_ttl_near_zero);

    RUN_TEST (test_heartbeat_notimeout_dealer_router);
    RUN_TEST (test_heartbeat_notimeout_req_rep);
    RUN_TEST (test_heartbeat_notimeout_pull_push);
    RUN_TEST (test_heartbeat_notimeout_sub_pub);
    RUN_TEST (test_heartbeat_notimeout_pair_pair);

    RUN_TEST (test_heartbeat_notimeout_dealer_router_with_curve);
    RUN_TEST (test_heartbeat_notimeout_req_rep_with_curve);
    RUN_TEST (test_heartbeat_notimeout_pull_push_with_curve);
    RUN_TEST (test_heartbeat_notimeout_sub_pub_with_curve);
    RUN_TEST (test_heartbeat_notimeout_pair_pair_with_curve);

#ifdef ZMQ_BUILD_DRAFT_API
    RUN_TEST (test_heartbeat_ttl_client_server);
    RUN_TEST (test_heartbeat_ttl_gather_scatter);

    RUN_TEST (test_heartbeat_notimeout_client_server);
    RUN_TEST (test_heartbeat_notimeout_gather_scatter);

    RUN_TEST (test_heartbeat_notimeout_client_server_with_curve);
    RUN_TEST (test_heartbeat_notimeout_gather_scatter_with_curve);
#endif

    return UNITY_END ();
}
