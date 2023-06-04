/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

SETUP_TEARDOWN_TESTCONTEXT

typedef void (*extra_func_t) (void *socket_);

void set_sockopt_bind_to_device (void *socket)
{
    const char device[] = "lo";
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (socket, ZMQ_BINDTODEVICE, &device, sizeof (device) - 1));
}

//  TODO this is duplicated from test_pair_tcp
void test_pair_tcp (extra_func_t extra_func_ = NULL)
{
    void *sb = test_context_socket (ZMQ_PAIR);

    if (extra_func_)
        extra_func_ (sb);

    char my_endpoint[MAX_SOCKET_STRING];
    size_t my_endpoint_length = sizeof my_endpoint;
    int rc = zmq_bind (sb, "tcp://127.0.0.1:*");
    if (rc < 0 && errno == EOPNOTSUPP)
        TEST_IGNORE_MESSAGE ("SO_BINDTODEVICE not supported");
    TEST_ASSERT_SUCCESS_ERRNO (rc);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (sb, ZMQ_LAST_ENDPOINT, my_endpoint, &my_endpoint_length));

    void *sc = test_context_socket (ZMQ_PAIR);
    if (extra_func_)
        extra_func_ (sc);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc, my_endpoint));

    bounce (sb, sc);

    test_context_socket_close (sc);
    test_context_socket_close (sb);
}

void test_pair_tcp_bind_to_device ()
{
    test_pair_tcp (set_sockopt_bind_to_device);
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_pair_tcp_bind_to_device);

    return UNITY_END ();
}
