/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

#include <stdlib.h>

void setUp ()
{
    setup_test_context ();
}

// This is our server task.
// It runs a proxy with a single REP socket as both frontend and backend.

void server_task (void * /*unused_*/)
{
    char my_endpoint[MAX_SOCKET_STRING];
    void *rep = zmq_socket (get_test_context (), ZMQ_REP);
    TEST_ASSERT_NOT_NULL (rep);
    bind_loopback_ipv4 (rep, my_endpoint, sizeof my_endpoint);

    // Control socket receives terminate command from main over inproc
    void *control = zmq_socket (get_test_context (), ZMQ_REQ);
    TEST_ASSERT_NOT_NULL (control);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (control, "inproc://control"));
    send_string_expect_success (control, my_endpoint, 0);

    // Use rep as both frontend and backend
    zmq_proxy (rep, rep, NULL);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_close (rep));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_close (control));
}


// The main thread simply starts several clients and a server, and then
// waits for the server to finish.
void test_proxy_single_socket ()
{
    void *server_thread = zmq_threadstart (&server_task, NULL);

    // Control socket receives terminate command from main over inproc
    void *control = test_context_socket (ZMQ_REP);
    TEST_ASSERT_NOT_NULL (control);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (control, "inproc://control"));
    char *my_endpoint = s_recv (control);
    TEST_ASSERT_NOT_NULL (my_endpoint);

    // client socket pings proxy over tcp
    void *req = test_context_socket (ZMQ_REQ);
    TEST_ASSERT_NOT_NULL (req);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (req, my_endpoint));

    send_string_expect_success (req, "msg1", 0);
    recv_string_expect_success (req, "msg1", 0);

    send_string_expect_success (req, "msg22", 0);
    recv_string_expect_success (req, "msg22", 0);

    test_context_socket_close (control);
    test_context_socket_close (req);
    teardown_test_context ();
    free (my_endpoint);

    zmq_threadclose (server_thread);
}

int main (void)
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_proxy_single_socket);
    return UNITY_END ();
}
