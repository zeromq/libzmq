/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

SETUP_TEARDOWN_TESTCONTEXT

void test_roundtrip ()
{
    void *sb = test_context_socket (ZMQ_REP);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (sb, "inproc://a"));

    void *sc = test_context_socket (ZMQ_REQ);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc, "inproc://a"));

    bounce (sb, sc);

    test_context_socket_close (sc);
    test_context_socket_close (sb);
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_roundtrip);
    return UNITY_END ();
}
