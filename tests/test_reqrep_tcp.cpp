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

SETUP_TEARDOWN_TESTCONTEXT

void test_single_connect (int ipv6_)
{
    size_t len = MAX_SOCKET_STRING;
    char my_endpoint[MAX_SOCKET_STRING];

    void *sb = test_context_socket (ZMQ_REP);
    bind_loopback (sb, ipv6_, my_endpoint, len);

    void *sc = test_context_socket (ZMQ_REQ);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sc, ZMQ_IPV6, &ipv6_, sizeof (int)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc, my_endpoint));

    bounce (sb, sc);

    // the sockets are disconnected and unbound explicitly in this test case
    // to check that this can be done successfully with the expected
    // endpoints/addresses

    TEST_ASSERT_SUCCESS_ERRNO (zmq_disconnect (sc, my_endpoint));

    TEST_ASSERT_SUCCESS_ERRNO (zmq_unbind (sb, my_endpoint));

    test_context_socket_close (sc);
    test_context_socket_close (sb);
}

void make_connect_address (char *connect_address_,
                           const int ipv6_,
                           const int port_,
                           const char *bind_address_)
{
    sprintf (connect_address_, "tcp://%s:%i;%s", ipv6_ ? "[::1]" : "127.0.0.1",
             port_, strrchr (bind_address_, '/') + 1);
}

void test_multi_connect (int ipv6_)
{
    size_t len = MAX_SOCKET_STRING;
    char my_endpoint_0[MAX_SOCKET_STRING];
    char my_endpoint_1[MAX_SOCKET_STRING];
    char my_endpoint_2[MAX_SOCKET_STRING];
    char my_endpoint_3[MAX_SOCKET_STRING * 2];

    void *sb0 = test_context_socket (ZMQ_REP);
    bind_loopback (sb0, ipv6_, my_endpoint_0, len);

    void *sb1 = test_context_socket (ZMQ_REP);
    bind_loopback (sb1, ipv6_, my_endpoint_1, len);

    void *sb2 = test_context_socket (ZMQ_REP);
    bind_loopback (sb2, ipv6_, my_endpoint_2, len);

    void *sc = test_context_socket (ZMQ_REQ);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sc, ZMQ_IPV6, &ipv6_, sizeof (int)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc, my_endpoint_0));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc, my_endpoint_1));
    make_connect_address (my_endpoint_3, ipv6_, 5564, my_endpoint_2);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc, my_endpoint_3));

    bounce (sb0, sc);
    bounce (sb1, sc);
    bounce (sb2, sc);
    bounce (sb0, sc);
    bounce (sb1, sc);
    bounce (sb2, sc);
    bounce (sb0, sc);

    /// see comment on zmq_disconnect/zmq_unbind in test_single_connect

    TEST_ASSERT_SUCCESS_ERRNO (zmq_disconnect (sc, my_endpoint_0));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_disconnect (sc, my_endpoint_3));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_disconnect (sc, my_endpoint_1));

    TEST_ASSERT_SUCCESS_ERRNO (zmq_unbind (sb0, my_endpoint_0));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_unbind (sb1, my_endpoint_1));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_unbind (sb2, my_endpoint_2));

    test_context_socket_close (sc);
    test_context_socket_close (sb0);
    test_context_socket_close (sb1);
    test_context_socket_close (sb2);
}

void test_multi_connect_same_port (int ipv6_)
{
    size_t len = MAX_SOCKET_STRING;
    char my_endpoint_0[MAX_SOCKET_STRING];
    char my_endpoint_1[MAX_SOCKET_STRING];
    char my_endpoint_2[MAX_SOCKET_STRING * 2];
    char my_endpoint_3[MAX_SOCKET_STRING * 2];
    char my_endpoint_4[MAX_SOCKET_STRING * 2];
    char my_endpoint_5[MAX_SOCKET_STRING * 2];

    void *sb0 = test_context_socket (ZMQ_REP);
    bind_loopback (sb0, ipv6_, my_endpoint_0, len);

    void *sb1 = test_context_socket (ZMQ_REP);
    bind_loopback (sb1, ipv6_, my_endpoint_1, len);

    void *sc0 = test_context_socket (ZMQ_REQ);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sc0, ZMQ_IPV6, &ipv6_, sizeof (int)));
    make_connect_address (my_endpoint_2, ipv6_, 5564, my_endpoint_0);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc0, my_endpoint_2));
    make_connect_address (my_endpoint_3, ipv6_, 5565, my_endpoint_1);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc0, my_endpoint_3));

    void *sc1 = test_context_socket (ZMQ_REQ);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sc1, ZMQ_IPV6, &ipv6_, sizeof (int)));
    make_connect_address (my_endpoint_4, ipv6_, 5565, my_endpoint_0);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc1, my_endpoint_4));
    make_connect_address (my_endpoint_5, ipv6_, 5564, my_endpoint_1);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc1, my_endpoint_5));

    bounce (sb0, sc0);
    bounce (sb1, sc0);
    bounce (sb0, sc1);
    bounce (sb1, sc1);
    bounce (sb0, sc0);
    bounce (sb1, sc0);

    /// see comment on zmq_disconnect/zmq_unbind in test_single_connect

    TEST_ASSERT_SUCCESS_ERRNO (zmq_disconnect (sc1, my_endpoint_4));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_disconnect (sc1, my_endpoint_5));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_disconnect (sc0, my_endpoint_2));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_disconnect (sc0, my_endpoint_3));

    TEST_ASSERT_SUCCESS_ERRNO (zmq_unbind (sb0, my_endpoint_0));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_unbind (sb1, my_endpoint_1));

    test_context_socket_close (sc0);
    test_context_socket_close (sc1);
    test_context_socket_close (sb0);
    test_context_socket_close (sb1);
}

void test_single_connect_ipv4 ()
{
    test_single_connect (false);
}

void test_multi_connect_ipv4 ()
{
    test_multi_connect (false);
}

void test_multi_connect_same_port_ipv4 ()
{
    test_multi_connect_same_port (false);
}

void test_single_connect_ipv6 ()
{
    test_single_connect (true);
}

void test_multi_connect_ipv6 ()
{
    test_multi_connect (true);
}

void test_multi_connect_same_port_ipv6 ()
{
    test_multi_connect_same_port (true);
}

int main (void)
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_single_connect_ipv4);
    RUN_TEST (test_multi_connect_ipv4);
    RUN_TEST (test_multi_connect_same_port_ipv4);
    RUN_TEST (test_single_connect_ipv6);
    RUN_TEST (test_multi_connect_ipv6);
    RUN_TEST (test_multi_connect_same_port_ipv6);

    return UNITY_END ();
}
