/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

SETUP_TEARDOWN_TESTCONTEXT

void test_ipc_wildcard ()
{
    void *sb = test_context_socket (ZMQ_PAIR);
    char endpoint[200];
    bind_loopback_ipc (sb, endpoint, sizeof endpoint);

    void *sc = test_context_socket (ZMQ_PAIR);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc, endpoint));

    bounce (sb, sc);

    test_context_socket_close (sc);
    test_context_socket_close (sb);
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_ipc_wildcard);
    return UNITY_END ();
}
