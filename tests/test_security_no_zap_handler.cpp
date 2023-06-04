/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

SETUP_TEARDOWN_TESTCONTEXT

void test_no_zap_handler ()
{
    //  We first test client/server with a ZAP domain but with no handler
    //  If there is no handler, libzmq should ignore the ZAP option unless
    //  ZMQ_ZAP_ENFORCE_DOMAIN is set
    void *server = test_context_socket (ZMQ_DEALER);
    void *client = test_context_socket (ZMQ_DEALER);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (server, ZMQ_ZAP_DOMAIN, "TEST", 5));
    char my_endpoint[MAX_SOCKET_STRING];
    bind_loopback_ipv4 (server, my_endpoint, sizeof my_endpoint);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (client, my_endpoint));
    bounce (server, client);
    test_context_socket_close_zero_linger (client);
    test_context_socket_close_zero_linger (server);
}

void test_no_zap_handler_enforce_domain ()
{
#ifdef ZMQ_ZAP_ENFORCE_DOMAIN
    //  Now set ZMQ_ZAP_ENFORCE_DOMAIN which strictly enforces the ZAP
    //  RFC but is backward-incompatible, now it should fail
    void *server = test_context_socket (ZMQ_DEALER);
    void *client = test_context_socket (ZMQ_DEALER);
    int required = 1;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (server, ZMQ_ZAP_ENFORCE_DOMAIN, &required, sizeof (int)));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (server, ZMQ_ZAP_DOMAIN, "TEST", 5));
    char my_endpoint[MAX_SOCKET_STRING];
    bind_loopback_ipv4 (server, my_endpoint, sizeof my_endpoint);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (client, my_endpoint));
    expect_bounce_fail (server, client);
    test_context_socket_close_zero_linger (client);
    test_context_socket_close_zero_linger (server);
#endif
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_no_zap_handler);
    RUN_TEST (test_no_zap_handler_enforce_domain);
    return UNITY_END ();
}
