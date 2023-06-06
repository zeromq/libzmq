/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

SETUP_TEARDOWN_TESTCONTEXT

void test_x ()
{
    void *sock = test_context_socket (ZMQ_PUB);

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_connect (sock, "tcp://127.0.0.1:0;localhost:1234"));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_connect (sock, "tcp://localhost:5555;localhost:1235"));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_connect (sock, "tcp://lo:5555;localhost:1235"));

    test_context_socket_close (sock);
}

int main (void)
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_x);
    return UNITY_END ();
}
