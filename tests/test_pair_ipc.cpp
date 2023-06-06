/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

#include <string>

SETUP_TEARDOWN_TESTCONTEXT

void test_roundtrip ()
{
    char my_endpoint[256];

    void *sb = test_context_socket (ZMQ_PAIR);
    bind_loopback_ipc (sb, my_endpoint, sizeof my_endpoint);

    void *sc = test_context_socket (ZMQ_PAIR);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc, my_endpoint));

    bounce (sb, sc);

    test_context_socket_close (sc);
    test_context_socket_close (sb);
}

static const char prefix[] = "ipc://";

void test_endpoint_too_long ()
{
    std::string endpoint_too_long;
    endpoint_too_long.append (prefix);
    for (size_t i = 0; i < 108; ++i) {
        endpoint_too_long.append ("a");
    }

    void *sb = test_context_socket (ZMQ_PAIR);
    // TODO ENAMETOOLONG is not listed in the errors returned by zmq_bind,
    // should this be EINVAL?
    TEST_ASSERT_FAILURE_ERRNO (ENAMETOOLONG,
                               zmq_bind (sb, endpoint_too_long.data ()));

    test_context_socket_close (sb);
}


int main (void)
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_roundtrip);
    RUN_TEST (test_endpoint_too_long);
    return UNITY_END ();
}
