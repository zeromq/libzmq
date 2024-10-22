/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

#include <stdlib.h>

SETUP_TEARDOWN_TESTCONTEXT

void test_leak ()
{
    char my_endpoint[256];

    void *sb = test_context_socket (ZMQ_REP);
    bind_loopback_ipc (sb, my_endpoint, sizeof my_endpoint);

    void *sc = test_context_socket (ZMQ_REQ);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc, my_endpoint));

    static const char leakymsg[] = "leakymsg";
    send_string_expect_success (sc, leakymsg, 0);

    char *buf = s_recv (sb);
    free (buf);

    test_context_socket_close (sc);

    msleep (SETTLE_TIME);

    send_string_expect_success (sb, leakymsg, 0);

    test_context_socket_close (sb);
}

void test_simple (void)
{
    char my_endpoint[256];

    void *sb = test_context_socket (ZMQ_REP);
    bind_loopback_ipc (sb, my_endpoint, sizeof my_endpoint);

    void *sc = test_context_socket (ZMQ_REQ);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc, my_endpoint));

    bounce (sb, sc);

    test_context_socket_close (sc);
    test_context_socket_close (sb);
}

int main (void)
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_simple);
    RUN_TEST (test_leak);
    return UNITY_END ();
}
