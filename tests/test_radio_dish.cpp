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

#include <string.h>

#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

// Helper macro to define the v4/v6 function pairs
#define MAKE_TEST_V4V6(_test)                                                  \
    static void _test##_ipv4 () { _test (false); }                             \
                                                                               \
    static void _test##_ipv6 ()                                                \
    {                                                                          \
        if (!is_ipv6_available ()) {                                           \
            TEST_IGNORE_MESSAGE ("ipv6 is not available");                     \
        }                                                                      \
        _test (true);                                                          \
    }

SETUP_TEARDOWN_TESTCONTEXT

void msg_send_expect_success (void *s_, const char *group_, const char *body_)
{
    zmq_msg_t msg;
    const size_t len = strlen (body_);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init_size (&msg, len));

    memcpy (zmq_msg_data (&msg), body_, len);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_set_group (&msg, group_));

    int rc = zmq_msg_send (&msg, s_, 0);
    TEST_ASSERT_EQUAL_INT ((int) len, rc);

    // TODO isn't the msg closed by zmq_msg_send?
    zmq_msg_close (&msg);
}

void msg_recv_cmp (void *s_, const char *group_, const char *body_)
{
    zmq_msg_t msg;
    const size_t len = strlen (body_);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init (&msg));

    int recv_rc = TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_recv (&msg, s_, 0));
    TEST_ASSERT_EQUAL_INT (len, recv_rc);

    TEST_ASSERT_EQUAL_STRING (group_, zmq_msg_group (&msg));

    TEST_ASSERT_EQUAL_STRING_LEN (body_, zmq_msg_data (&msg), len);

    zmq_msg_close (&msg);
}

void test_leave_unjoined_fails ()
{
    void *dish = test_context_socket (ZMQ_DISH);

    //  Leaving a group which we didn't join
    TEST_ASSERT_FAILURE_ERRNO (EINVAL, zmq_leave (dish, "Movies"));

    test_context_socket_close (dish);
}

void test_join_too_long_fails ()
{
    void *dish = test_context_socket (ZMQ_DISH);

    //  Joining too long group
    char too_long_group[ZMQ_GROUP_MAX_LENGTH + 2];
    for (int index = 0; index < ZMQ_GROUP_MAX_LENGTH + 2; index++)
        too_long_group[index] = 'A';
    too_long_group[ZMQ_GROUP_MAX_LENGTH + 1] = '\0';
    TEST_ASSERT_FAILURE_ERRNO (EINVAL, zmq_join (dish, too_long_group));

    test_context_socket_close (dish);
}

void test_join_twice_fails ()
{
    void *dish = test_context_socket (ZMQ_DISH);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_join (dish, "Movies"));

    // Duplicate Joining
    TEST_ASSERT_FAILURE_ERRNO (EINVAL, zmq_join (dish, "Movies"));

    test_context_socket_close (dish);
}

void test_radio_dish_tcp_poll (int ipv6_)
{
    size_t len = MAX_SOCKET_STRING;
    char my_endpoint[MAX_SOCKET_STRING];

    void *radio = test_context_socket (ZMQ_RADIO);
    bind_loopback (radio, ipv6_, my_endpoint, len);

    void *dish = test_context_socket (ZMQ_DISH);

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (dish, ZMQ_IPV6, &ipv6_, sizeof (int)));

    // Joining
    TEST_ASSERT_SUCCESS_ERRNO (zmq_join (dish, "Movies"));

    // Connecting
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (dish, my_endpoint));

    msleep (SETTLE_TIME);

    //  This is not going to be sent as dish only subscribe to "Movies"
    msg_send_expect_success (radio, "TV", "Friends");

    //  This is going to be sent to the dish
    msg_send_expect_success (radio, "Movies", "Godfather");

    //  Check the correct message arrived
    msg_recv_cmp (dish, "Movies", "Godfather");

    //  Join group during connection optvallen
    TEST_ASSERT_SUCCESS_ERRNO (zmq_join (dish, "TV"));

    zmq_sleep (1);

    //  This should arrive now as we joined the group
    msg_send_expect_success (radio, "TV", "Friends");

    //  Check the correct message arrived
    msg_recv_cmp (dish, "TV", "Friends");

    //  Leaving group
    TEST_ASSERT_SUCCESS_ERRNO (zmq_leave (dish, "TV"));

    zmq_sleep (1);

    //  This is not going to be sent as dish only subscribe to "Movies"
    msg_send_expect_success (radio, "TV", "Friends");

    //  This is going to be sent to the dish
    msg_send_expect_success (radio, "Movies", "Godfather");

    // test zmq_poll with dish
    zmq_pollitem_t items[] = {
      {radio, 0, ZMQ_POLLIN, 0}, // read publications
      {dish, 0, ZMQ_POLLIN, 0},  // read subscriptions
    };
    int rc = zmq_poll (items, 2, 2000);
    TEST_ASSERT_EQUAL_INT (1, rc);
    TEST_ASSERT_EQUAL_INT (ZMQ_POLLIN, items[1].revents);

    //  Check the correct message arrived
    msg_recv_cmp (dish, "Movies", "Godfather");

    test_context_socket_close (dish);
    test_context_socket_close (radio);
}
MAKE_TEST_V4V6 (test_radio_dish_tcp_poll)

void test_dish_connect_fails (int ipv6_)
{
    void *dish = test_context_socket (ZMQ_DISH);

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (dish, ZMQ_IPV6, &ipv6_, sizeof (int)));

    const char *url = ipv6_ ? "udp://[::1]:5556" : "udp://127.0.0.1:5556";

    //  Connecting dish should fail
    TEST_ASSERT_FAILURE_ERRNO (ENOCOMPATPROTO, zmq_connect (dish, url));

    test_context_socket_close (dish);
}
MAKE_TEST_V4V6 (test_dish_connect_fails)

void test_radio_bind_fails (int ipv6_)
{
    void *radio = test_context_socket (ZMQ_RADIO);

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (radio, ZMQ_IPV6, &ipv6_, sizeof (int)));

    //  Connecting dish should fail
    //  Bind radio should fail
    TEST_ASSERT_FAILURE_ERRNO (ENOCOMPATPROTO,
                               zmq_bind (radio, "udp://*:5556"));

    test_context_socket_close (radio);
}
MAKE_TEST_V4V6 (test_radio_bind_fails)

void test_radio_dish_udp (int ipv6_)
{
    void *radio = test_context_socket (ZMQ_RADIO);
    void *dish = test_context_socket (ZMQ_DISH);

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (radio, ZMQ_IPV6, &ipv6_, sizeof (int)));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (dish, ZMQ_IPV6, &ipv6_, sizeof (int)));

    const char *radio_url = ipv6_ ? "udp://[::1]:5556" : "udp://127.0.0.1:5556";

    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (dish, "udp://*:5556"));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (radio, radio_url));

    msleep (SETTLE_TIME);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_join (dish, "TV"));

    msg_send_expect_success (radio, "TV", "Friends");
    msg_recv_cmp (dish, "TV", "Friends");

    test_context_socket_close (dish);
    test_context_socket_close (radio);
}
MAKE_TEST_V4V6 (test_radio_dish_udp)

#define MCAST_IPV4 "226.8.5.5"
#define MCAST_IPV6 "ff02::7a65:726f:6df1:0a01"

static const char *mcast_url (int ipv6_)
{
    if (ipv6_) {
        return "udp://[" MCAST_IPV6 "]:5555";
    } else {
        return "udp://" MCAST_IPV4 ":5555";
    }
}

//  OSX uses a different name for this socket option
#ifndef IPV6_ADD_MEMBERSHIP
#define IPV6_ADD_MEMBERSHIP IPV6_JOIN_GROUP
#endif

union sa_u
{
    struct sockaddr generic;
    struct sockaddr_in ipv4;
    struct sockaddr_in6 ipv6;
};

//  Test if multicast is available on this machine by attempting to
//  send a receive a multicast datagram
static bool is_multicast_available (int ipv6_)
{
    int family = ipv6_ ? AF_INET6 : AF_INET;
    fd_t bind_sock = retired_fd;
    fd_t send_sock = retired_fd;
    int port = 5555;
    bool success = false;
    const char *msg = "it works";
    char buf[32];
    union sa_u any;
    union sa_u mcast;
    socklen_t sl;
    int rc;

    if (ipv6_) {
        struct sockaddr_in6 *any_ipv6 = &any.ipv6;
        struct sockaddr_in6 *mcast_ipv6 = &mcast.ipv6;

        any_ipv6->sin6_family = AF_INET6;
        any_ipv6->sin6_port = htons (port);
        any_ipv6->sin6_flowinfo = 0;
        any_ipv6->sin6_scope_id = 0;

        rc = inet_pton (AF_INET6, "::", &any_ipv6->sin6_addr);
        if (rc == 0) {
            goto out;
        }

        *mcast_ipv6 = *any_ipv6;

        rc = inet_pton (AF_INET6, MCAST_IPV6, &mcast_ipv6->sin6_addr);
        if (rc == 0) {
            goto out;
        }

        sl = sizeof (*any_ipv6);
    } else {
        struct sockaddr_in *any_ipv4 = &any.ipv4;
        struct sockaddr_in *mcast_ipv4 = &mcast.ipv4;

        any_ipv4->sin_family = AF_INET;
        any_ipv4->sin_port = htons (5555);

        rc = inet_pton (AF_INET, "0.0.0.0", &any_ipv4->sin_addr);
        if (rc == 0) {
            goto out;
        }

        *mcast_ipv4 = *any_ipv4;

        rc = inet_pton (AF_INET, MCAST_IPV4, &mcast_ipv4->sin_addr);
        if (rc == 0) {
            goto out;
        }

        sl = sizeof (*any_ipv4);
    }

    bind_sock = socket (family, SOCK_DGRAM, IPPROTO_UDP);
    if (bind_sock < 0) {
        goto out;
    }

    send_sock = socket (family, SOCK_DGRAM, IPPROTO_UDP);
    if (bind_sock < 0) {
        goto out;
    }

    rc = bind (bind_sock, &any.generic, sl);
    if (rc < 0) {
        goto out;
    }

    if (ipv6_) {
        struct ipv6_mreq mreq;
        struct sockaddr_in6 *mcast_ipv6 = &mcast.ipv6;

        mreq.ipv6mr_multiaddr = mcast_ipv6->sin6_addr;
        mreq.ipv6mr_interface = 0;

        rc = setsockopt (bind_sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP,
                         as_setsockopt_opt_t (&mreq), sizeof (mreq));
        if (rc < 0) {
            goto out;
        }

        int loop = 1;
        rc = setsockopt (send_sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
                         as_setsockopt_opt_t (&loop), sizeof (loop));
        if (rc < 0) {
            goto out;
        }
    } else {
        struct ip_mreq mreq;
        struct sockaddr_in *mcast_ipv4 = &mcast.ipv4;

        mreq.imr_multiaddr = mcast_ipv4->sin_addr;
        mreq.imr_interface.s_addr = htonl (INADDR_ANY);

        rc = setsockopt (bind_sock, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                         as_setsockopt_opt_t (&mreq), sizeof (mreq));
        if (rc < 0) {
            goto out;
        }

        int loop = 1;
        rc = setsockopt (send_sock, IPPROTO_IP, IP_MULTICAST_LOOP,
                         as_setsockopt_opt_t (&loop), sizeof (loop));
        if (rc < 0) {
            goto out;
        }
    }

    msleep (SETTLE_TIME);

    rc = sendto (send_sock, msg, static_cast<socklen_t> (strlen (msg)), 0,
                 &mcast.generic, sl);
    if (rc < 0) {
        goto out;
    }

    msleep (SETTLE_TIME);

    rc = recvfrom (bind_sock, buf, sizeof (buf) - 1, 0, NULL, 0);
    if (rc < 0) {
        goto out;
    }

    buf[rc] = '\0';

    success = (strcmp (msg, buf) == 0);

out:
    if (bind_sock >= 0) {
        close (bind_sock);
    }

    if (send_sock >= 0) {
        close (send_sock);
    }

    return success;
}

static void ignore_if_unavailable (int ipv6_)
{
    if (ipv6_ && !is_ipv6_available ())
        TEST_IGNORE_MESSAGE ("No IPV6 available");
    if (!is_multicast_available (ipv6_))
        TEST_IGNORE_MESSAGE ("No multicast available");
}

static void test_radio_dish_mcast (int ipv6_)
{
    ignore_if_unavailable (ipv6_);

    void *radio = test_context_socket (ZMQ_RADIO);
    void *dish = test_context_socket (ZMQ_DISH);

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (radio, ZMQ_IPV6, &ipv6_, sizeof (int)));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (dish, ZMQ_IPV6, &ipv6_, sizeof (int)));

    const char *url = mcast_url (ipv6_);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (dish, url));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (radio, url));

    msleep (SETTLE_TIME);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_join (dish, "TV"));

    msg_send_expect_success (radio, "TV", "Friends");
    msg_recv_cmp (dish, "TV", "Friends");

    test_context_socket_close (dish);
    test_context_socket_close (radio);
}
MAKE_TEST_V4V6 (test_radio_dish_mcast)

static void test_radio_dish_no_loop (int ipv6_)
{
#ifdef _WIN32
    TEST_IGNORE_MESSAGE (
      "ZMQ_MULTICAST_LOOP=false does not appear to work on Windows (TODO)");
#endif
    ignore_if_unavailable (ipv6_);

    void *radio = test_context_socket (ZMQ_RADIO);
    void *dish = test_context_socket (ZMQ_DISH);

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (radio, ZMQ_IPV6, &ipv6_, sizeof (int)));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (dish, ZMQ_IPV6, &ipv6_, sizeof (int)));

    //  Disable multicast loop for radio
    int loop = 0;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (radio, ZMQ_MULTICAST_LOOP, &loop, sizeof (int)));

    const char *url = mcast_url (ipv6_);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (dish, url));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (radio, url));

    msleep (SETTLE_TIME);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_join (dish, "TV"));

    msg_send_expect_success (radio, "TV", "Friends");

    // Looping is disabled, we shouldn't receive anything
    msleep (SETTLE_TIME);

    TEST_ASSERT_FAILURE_ERRNO (EAGAIN, zmq_recv (dish, NULL, 0, ZMQ_DONTWAIT));

    test_context_socket_close (dish);
    test_context_socket_close (radio);
}
MAKE_TEST_V4V6 (test_radio_dish_no_loop)

int main (void)
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_leave_unjoined_fails);
    RUN_TEST (test_join_too_long_fails);
    RUN_TEST (test_join_twice_fails);
    RUN_TEST (test_radio_bind_fails_ipv4);
    RUN_TEST (test_radio_bind_fails_ipv6);
    RUN_TEST (test_dish_connect_fails_ipv4);
    RUN_TEST (test_dish_connect_fails_ipv6);
    RUN_TEST (test_radio_dish_tcp_poll_ipv4);
    RUN_TEST (test_radio_dish_tcp_poll_ipv6);
    RUN_TEST (test_radio_dish_udp_ipv4);
    RUN_TEST (test_radio_dish_udp_ipv6);

    RUN_TEST (test_radio_dish_mcast_ipv4);
    RUN_TEST (test_radio_dish_no_loop_ipv4);

    RUN_TEST (test_radio_dish_mcast_ipv6);
    RUN_TEST (test_radio_dish_no_loop_ipv6);

    return UNITY_END ();
}
