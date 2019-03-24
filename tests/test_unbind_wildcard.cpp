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
#include "testutil_unity.hpp"

#include <string.h>

SETUP_TEARDOWN_TESTCONTEXT

void test_address_wildcard_ipv4 ()
{
    /* Address wildcard, IPv6 disabled */
    void *sb = test_context_socket (ZMQ_REP);
    void *sc = test_context_socket (ZMQ_REQ);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (sb, "tcp://*:*"));

    char bind_endpoint[256];
    char connect_endpoint[256];
    size_t endpoint_len = sizeof (bind_endpoint);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (sb, ZMQ_LAST_ENDPOINT, bind_endpoint, &endpoint_len));

    //  Apparently Windows can't connect to 0.0.0.0. A better fix would be welcome.
#ifdef ZMQ_HAVE_WINDOWS
    sprintf (connect_endpoint, "tcp://127.0.0.1:%s",
             strrchr (bind_endpoint, ':') + 1);
#else
    strcpy (connect_endpoint, bind_endpoint);
#endif

    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc, connect_endpoint));

    bounce (sb, sc);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_disconnect (sc, connect_endpoint));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_unbind (sb, bind_endpoint));

    test_context_socket_close (sc);
    test_context_socket_close (sb);
}

void test_address_wildcard_ipv6 ()
{
    int ipv6 = is_ipv6_available ();

    /* Address wildcard, IPv6 enabled */
    void *sb = test_context_socket (ZMQ_REP);
    void *sc = test_context_socket (ZMQ_REQ);

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sb, ZMQ_IPV6, &ipv6, sizeof (int)));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sc, ZMQ_IPV6, &ipv6, sizeof (int)));

    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (sb, "tcp://*:*"));

    char bind_endpoint[256];
    char connect_endpoint[256];
    size_t endpoint_len = sizeof (bind_endpoint);
    memset (bind_endpoint, 0, endpoint_len);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (sb, ZMQ_LAST_ENDPOINT, bind_endpoint, &endpoint_len));

#ifdef ZMQ_HAVE_WINDOWS
    if (ipv6)
        sprintf (connect_endpoint, "tcp://[::1]:%s",
                 strrchr (bind_endpoint, ':') + 1);
    else
        sprintf (connect_endpoint, "tcp://127.0.0.1:%s",
                 strrchr (bind_endpoint, ':') + 1);
#else
    strcpy (connect_endpoint, bind_endpoint);
#endif

    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc, connect_endpoint));

    bounce (sb, sc);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_disconnect (sc, connect_endpoint));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_unbind (sb, bind_endpoint));

    test_context_socket_close (sc);
    test_context_socket_close (sb);
}

void test_port_wildcard_ipv4_address ()
{
    /* Port wildcard, IPv4 address, IPv6 disabled */
    void *sb = test_context_socket (ZMQ_REP);
    void *sc = test_context_socket (ZMQ_REQ);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (sb, "tcp://127.0.0.1:*"));

    char endpoint[256];
    size_t endpoint_len = sizeof (endpoint);
    memset (endpoint, 0, endpoint_len);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (sb, ZMQ_LAST_ENDPOINT, endpoint, &endpoint_len));

    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc, endpoint));

    bounce (sb, sc);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_disconnect (sc, endpoint));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_unbind (sb, endpoint));

    test_context_socket_close (sc);
    test_context_socket_close (sb);
}

void test_port_wildcard_ipv4_address_ipv6 ()
{
    /* Port wildcard, IPv4 address, IPv6 enabled */
    void *sb = test_context_socket (ZMQ_REP);
    void *sc = test_context_socket (ZMQ_REQ);

    const int ipv6 = is_ipv6_available ();
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sb, ZMQ_IPV6, &ipv6, sizeof (int)));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sc, ZMQ_IPV6, &ipv6, sizeof (int)));

    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (sb, "tcp://127.0.0.1:*"));

    char endpoint[256];
    size_t endpoint_len = sizeof (endpoint);
    memset (endpoint, 0, endpoint_len);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (sb, ZMQ_LAST_ENDPOINT, endpoint, &endpoint_len));

    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc, endpoint));

    bounce (sb, sc);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_disconnect (sc, endpoint));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_unbind (sb, endpoint));

    test_context_socket_close (sc);
    test_context_socket_close (sb);
}

void test_port_wildcard_ipv6_address ()
{
    const int ipv6 = is_ipv6_available ();
    if (!ipv6)
        TEST_IGNORE_MESSAGE ("ipv6 is not available");

    /* Port wildcard, IPv6 address, IPv6 enabled */
    void *sb = test_context_socket (ZMQ_REP);
    void *sc = test_context_socket (ZMQ_REQ);

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sb, ZMQ_IPV6, &ipv6, sizeof (int)));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sc, ZMQ_IPV6, &ipv6, sizeof (int)));

    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (sb, "tcp://[::1]:*"));

    char endpoint[256];
    size_t endpoint_len = sizeof (endpoint);
    memset (endpoint, 0, endpoint_len);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (sb, ZMQ_LAST_ENDPOINT, endpoint, &endpoint_len));

    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc, endpoint));

    bounce (sb, sc);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_disconnect (sc, endpoint));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_unbind (sb, endpoint));

    test_context_socket_close (sc);
    test_context_socket_close (sb);
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_address_wildcard_ipv4);
    RUN_TEST (test_address_wildcard_ipv6);
    RUN_TEST (test_port_wildcard_ipv4_address);
    RUN_TEST (test_port_wildcard_ipv4_address_ipv6);
    RUN_TEST (test_port_wildcard_ipv6_address);
    return UNITY_END ();
}
