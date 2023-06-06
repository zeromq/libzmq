/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

SETUP_TEARDOWN_TESTCONTEXT

void test_diffserv ()
{
    int tos = 0x28;
    int o_tos;
    size_t tos_size = sizeof (tos);
    char my_endpoint[MAX_SOCKET_STRING];

    void *sb = test_context_socket (ZMQ_PAIR);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (sb, ZMQ_TOS, &tos, tos_size));
    bind_loopback_ipv4 (sb, my_endpoint, sizeof (my_endpoint));

    TEST_ASSERT_SUCCESS_ERRNO (zmq_getsockopt (sb, ZMQ_TOS, &o_tos, &tos_size));
    TEST_ASSERT_EQUAL (tos, o_tos);

    void *sc = test_context_socket (ZMQ_PAIR);
    tos = 0x58;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (sc, ZMQ_TOS, &tos, tos_size));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc, my_endpoint));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_getsockopt (sc, ZMQ_TOS, &o_tos, &tos_size));
    TEST_ASSERT_EQUAL (tos, o_tos);

    // Wireshark can be used to verify that the server socket is
    // using DSCP 0x28 in packets to the client while the client
    // is using 0x58 in packets to the server.
    bounce (sb, sc);

    test_context_socket_close (sc);
    test_context_socket_close (sb);
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_diffserv);
    return UNITY_END ();
}
