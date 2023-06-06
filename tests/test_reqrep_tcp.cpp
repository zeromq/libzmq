/* SPDX-License-Identifier: MPL-2.0 */

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
    if (ipv6_)
        snprintf (connect_address_, 30 * sizeof (char), "tcp://[::1]:%i;%s",
                  port_, strrchr (bind_address_, '/') + 1);
    else
        snprintf (connect_address_, 38 * sizeof (char), "tcp://127.0.0.1:%i;%s",
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
