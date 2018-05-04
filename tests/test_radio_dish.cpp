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

#include <unity.h>

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

void setUp ()
{
    setup_test_context ();
}

void tearDown ()
{
    teardown_test_context ();
}

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

    return UNITY_END ();
}
