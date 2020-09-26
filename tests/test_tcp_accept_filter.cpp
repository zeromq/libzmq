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

#include "testutil.hpp"
#include "testutil_unity.hpp"

#include <cstring>

SETUP_TEARDOWN_TESTCONTEXT

void test_reconnect_ivl_against_pair_socket (const char *my_endpoint_,
                                             void *sb_)
{
    void *sc = test_context_socket (ZMQ_PAIR);
    int interval = -1;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sc, ZMQ_RECONNECT_IVL, &interval, sizeof (int)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc, my_endpoint_));

    bounce (sb_, sc);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_unbind (sb_, my_endpoint_));

    expect_bounce_fail (sb_, sc);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (sb_, my_endpoint_));

    expect_bounce_fail (sb_, sc);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc, my_endpoint_));

    bounce (sb_, sc);

    test_context_socket_close (sc);
}

void test_reconnect_ivl_tcp (bind_function_t bind_function_)
{
    char my_endpoint[MAX_SOCKET_STRING];

    void *sb = test_context_socket (ZMQ_PAIR);
    bind_function_ (sb, my_endpoint, sizeof my_endpoint);

    test_reconnect_ivl_against_pair_socket (my_endpoint, sb);
    test_context_socket_close (sb);
}

void test_bad_filter_string (const char *const filter_)
{
    void *socket = test_context_socket (ZMQ_PAIR);

    TEST_ASSERT_FAILURE_ERRNO (EINVAL,
                               zmq_setsockopt (socket, ZMQ_TCP_ACCEPT_FILTER,
                                               filter_, strlen (filter_)));

    test_context_socket_close (socket);
}

#define TEST_BAD_FILTER_STRING(case, filter)                                   \
    void test_bad_filter_string_##case () { test_bad_filter_string (filter); }

TEST_BAD_FILTER_STRING (foo, "foo")
TEST_BAD_FILTER_STRING (zeros_foo, "0.0.0.0foo")
TEST_BAD_FILTER_STRING (zeros_foo_mask, "0.0.0.0/foo")
TEST_BAD_FILTER_STRING (zeros_empty_mask, "0.0.0.0/")
TEST_BAD_FILTER_STRING (zeros_negative_mask, "0.0.0.0/-1")
TEST_BAD_FILTER_STRING (zeros_too_large_mask, "0.0.0.0/33")

void test_clear ()
{
    void *bind_socket = test_context_socket (ZMQ_PAIR);

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (bind_socket, ZMQ_TCP_ACCEPT_FILTER, NULL, 0));

#if 0
    // XXX Shouldn't this work as well?
    const char empty_filter[] = "";
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      socket, ZMQ_TCP_ACCEPT_FILTER, empty_filter, strlen (empty_filter)));
#endif

    char endpoint[MAX_SOCKET_STRING];
    bind_loopback_ipv4 (bind_socket, endpoint, sizeof (endpoint));

    void *connect_socket = test_context_socket (ZMQ_PAIR);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (connect_socket, endpoint));

    bounce (bind_socket, connect_socket);

    test_context_socket_close (connect_socket);
    test_context_socket_close (bind_socket);
}

const char non_matching_filter[] = "127.0.0.255/32";

void test_set_non_matching_and_clear ()
{
    void *bind_socket = test_context_socket (ZMQ_PAIR);

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (bind_socket, ZMQ_TCP_ACCEPT_FILTER, non_matching_filter,
                      strlen (non_matching_filter)));

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (bind_socket, ZMQ_TCP_ACCEPT_FILTER, NULL, 0));

    char endpoint[MAX_SOCKET_STRING];
    bind_loopback_ipv4 (bind_socket, endpoint, sizeof (endpoint));

    void *connect_socket = test_context_socket (ZMQ_PAIR);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (connect_socket, endpoint));

    bounce (bind_socket, connect_socket);

    test_context_socket_close (connect_socket);
    test_context_socket_close (bind_socket);
}

void test_set_matching (const char *const filter_)
{
    void *bind_socket = test_context_socket (ZMQ_PAIR);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      bind_socket, ZMQ_TCP_ACCEPT_FILTER, filter_, strlen (filter_)));

    char endpoint[MAX_SOCKET_STRING];
    bind_loopback_ipv4 (bind_socket, endpoint, sizeof (endpoint));

    void *connect_socket = test_context_socket (ZMQ_PAIR);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (connect_socket, endpoint));

    bounce (bind_socket, connect_socket);

    test_context_socket_close (connect_socket);
    test_context_socket_close (bind_socket);
}

void test_set_matching_1 ()
{
    test_set_matching ("127.0.0.1/32");
}

void test_set_matching_2 ()
{
    test_set_matching ("0.0.0.0/0");
}

void test_set_non_matching ()
{
    void *bind_socket = test_context_socket (ZMQ_PAIR);

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (bind_socket, ZMQ_TCP_ACCEPT_FILTER, non_matching_filter,
                      strlen (non_matching_filter)));

    char endpoint[MAX_SOCKET_STRING];
    bind_loopback_ipv4 (bind_socket, endpoint, sizeof (endpoint));

    void *connect_socket = test_context_socket (ZMQ_PAIR);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (connect_socket, endpoint));

    expect_bounce_fail (bind_socket, connect_socket);

    test_context_socket_close_zero_linger (connect_socket);
    test_context_socket_close_zero_linger (bind_socket);
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_bad_filter_string_foo);
    RUN_TEST (test_bad_filter_string_zeros_foo);
    RUN_TEST (test_bad_filter_string_zeros_foo_mask);
    RUN_TEST (test_bad_filter_string_zeros_empty_mask);
    RUN_TEST (test_bad_filter_string_zeros_negative_mask);
    RUN_TEST (test_bad_filter_string_zeros_too_large_mask);

    RUN_TEST (test_clear);
    RUN_TEST (test_set_non_matching_and_clear);
    RUN_TEST (test_set_matching_1);
    RUN_TEST (test_set_matching_2);

    RUN_TEST (test_set_non_matching);

    return UNITY_END ();
}
