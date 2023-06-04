/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

#include <stdlib.h>

void setUp ()
{
    setup_test_context ();
}

// This is a test for issue #1382. The server thread creates a SUB-PUSH
// steerable proxy. The main process then sends messages to the SUB
// but there is no pull on the other side, previously the proxy blocks
// in writing to the backend, preventing the proxy from terminating

void server_task (void * /*unused_*/)
{
    char my_endpoint[MAX_SOCKET_STRING];
    // Frontend socket talks to main process
    void *frontend = zmq_socket (get_test_context (), ZMQ_SUB);
    TEST_ASSERT_NOT_NULL (frontend);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (frontend, ZMQ_SUBSCRIBE, "", 0));
    bind_loopback_ipv4 (frontend, my_endpoint, sizeof my_endpoint);

    // Nice socket which is never read
    void *backend = zmq_socket (get_test_context (), ZMQ_PUSH);
    TEST_ASSERT_NOT_NULL (backend);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (backend, "tcp://127.0.0.1:*"));

    // Control socket receives terminate command from main over inproc
    void *control = zmq_socket (get_test_context (), ZMQ_REQ);
    TEST_ASSERT_NOT_NULL (control);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (control, "inproc://control"));
    send_string_expect_success (control, my_endpoint, 0);

    // Connect backend to frontend via a proxy
    zmq_proxy (frontend, backend, NULL);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_close (frontend));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_close (backend));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_close (control));
}


// The main thread simply starts a basic steerable proxy server, publishes some messages, and then
// waits for the server to terminate.
void test_proxy_terminate ()
{
    void *thread = zmq_threadstart (&server_task, NULL);

    // Control socket receives terminate command from main over inproc
    void *control = test_context_socket (ZMQ_REP);
    TEST_ASSERT_NOT_NULL (control);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (control, "inproc://control"));
    char *my_endpoint = s_recv (control);
    TEST_ASSERT_NOT_NULL (my_endpoint);

    msleep (500); // Run for 500 ms

    // Start a secondary publisher which writes data to the SUB-PUSH server socket
    void *publisher = test_context_socket (ZMQ_PUB);
    TEST_ASSERT_NOT_NULL (publisher);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (publisher, my_endpoint));

    msleep (SETTLE_TIME);
    send_string_expect_success (publisher, "This is a test", 0);

    msleep (50);
    send_string_expect_success (publisher, "This is a test", 0);

    msleep (50);
    send_string_expect_success (publisher, "This is a test", 0);

    test_context_socket_close (publisher);
    test_context_socket_close (control);
    teardown_test_context ();
    free (my_endpoint);

    zmq_threadclose (thread);
}

int main (void)
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_proxy_terminate);
    return UNITY_END ();
}
