/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

SETUP_TEARDOWN_TESTCONTEXT

void test_scatter_gather_multipart_fails ()
{
    void *scatter = test_context_socket (ZMQ_SCATTER);
    void *gather = test_context_socket (ZMQ_GATHER);

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_bind (scatter, "inproc://test-scatter-gather"));

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_connect (gather, "inproc://test-scatter-gather"));

    //  Should fail, multipart is not supported
    TEST_ASSERT_FAILURE_ERRNO (EINVAL,
                               zmq_send_const (scatter, "1", 1, ZMQ_SNDMORE));

    test_context_socket_close (scatter);
    test_context_socket_close (gather);
}

void test_scatter_gather ()
{
    void *scatter = test_context_socket (ZMQ_SCATTER);
    void *gather = test_context_socket (ZMQ_GATHER);
    void *gather2 = test_context_socket (ZMQ_GATHER);

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_bind (scatter, "inproc://test-scatter-gather"));

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_connect (gather, "inproc://test-scatter-gather"));

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_connect (gather2, "inproc://test-scatter-gather"));

    send_string_expect_success (scatter, "1", 0);
    send_string_expect_success (scatter, "2", 0);

    recv_string_expect_success (gather, "1", 0);
    recv_string_expect_success (gather2, "2", 0);

    test_context_socket_close (scatter);
    test_context_socket_close (gather);
    test_context_socket_close (gather2);
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_scatter_gather);
    RUN_TEST (test_scatter_gather_multipart_fails);
    return UNITY_END ();
}
