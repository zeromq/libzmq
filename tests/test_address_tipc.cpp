/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

SETUP_TEARDOWN_TESTCONTEXT

void test_tipc_port_name_and_domain ()
{
    // test Port Name addressing
    void *sb = test_context_socket (ZMQ_REP);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (sb, "tipc://{5560,0,0}"));

    void *sc = test_context_socket (ZMQ_REQ);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc, "tipc://{5560,0}@0.0.0"));

    bounce (sb, sc);

    test_context_socket_close (sc);
    test_context_socket_close (sb);
}

void test_tipc_port_identity ()
{
    char endpoint[256];
    unsigned int z, c, n, ref;

    void *sb = test_context_socket (ZMQ_REP);
    void *sc = test_context_socket (ZMQ_REQ);

    // Test binding to random Port Identity and
    // test resolving assigned address, should return a properly formatted string
    bind_loopback_tipc (sb, endpoint, sizeof endpoint);

    int rc = sscanf (&endpoint[0], "tipc://<%u.%u.%u:%u>", &z, &c, &n, &ref);
    TEST_ASSERT_EQUAL_INT (4, rc);

    TEST_ASSERT_NOT_EQUAL_MESSAGE (
      0, ref, "tipc port number must not be 0 after random assignment");

    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc, endpoint));

    bounce (sb, sc);

    test_context_socket_close (sc);
    test_context_socket_close (sb);
}

void test_tipc_bad_addresses ()
{
    // Test Port Name addressing
    void *sb = test_context_socket (ZMQ_REP);

    // Test binding to a fixed address, should fail
    TEST_ASSERT_FAILURE_ERRNO (EINVAL, zmq_bind (sb, "tipc://<1.2.3:123123>"));

    // Test connecting to random identity, should fail
    TEST_ASSERT_FAILURE_ERRNO (EINVAL, zmq_connect (sb, "tipc://<*>"));

    // Clean up
    test_context_socket_close (sb);
}


int main ()
{
    setup_test_environment ();

    if (!is_tipc_available ()) {
        printf ("TIPC environment unavailable, skipping test\n");
        return 77;
    }

    UNITY_BEGIN ();
    RUN_TEST (test_tipc_port_name_and_domain);
    RUN_TEST (test_tipc_port_identity);
    RUN_TEST (test_tipc_bad_addresses);

    return UNITY_END ();
}
