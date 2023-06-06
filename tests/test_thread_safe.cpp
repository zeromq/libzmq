/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

SETUP_TEARDOWN_TESTCONTEXT

//  Client threads loop on send/recv until told to exit
void client_thread (void *client_)
{
    for (int count = 0; count < 15000; count++) {
        send_string_expect_success (client_, "0", 0);
    }
    send_string_expect_success (client_, "1", 0);
}

void test_thread_safe ()
{
    char my_endpoint[MAX_SOCKET_STRING];

    void *server = test_context_socket (ZMQ_SERVER);
    bind_loopback_ipv4 (server, my_endpoint, sizeof my_endpoint);

    void *client = test_context_socket (ZMQ_CLIENT);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (client, my_endpoint));

    void *t1 = zmq_threadstart (client_thread, client);
    void *t2 = zmq_threadstart (client_thread, client);

    char data;
    int threads_completed = 0;
    while (threads_completed < 2) {
        TEST_ASSERT_SUCCESS_ERRNO (zmq_recv (server, &data, 1, 0));
        if (data == '1')
            threads_completed++; //  Thread ended
    }
    zmq_threadclose (t1);
    zmq_threadclose (t2);

    test_context_socket_close (server);
    test_context_socket_close (client);
}

void test_getsockopt_thread_safe (void *const socket_)
{
    int thread_safe;
    size_t size = sizeof (int);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (socket_, ZMQ_THREAD_SAFE, &thread_safe, &size));
    TEST_ASSERT_EQUAL_INT (1, thread_safe);
}

void test_client_getsockopt_thread_safe ()
{
    void *client = test_context_socket (ZMQ_CLIENT);
    test_getsockopt_thread_safe (client);
    test_context_socket_close (client);
}

void test_server_getsockopt_thread_safe ()
{
    void *server = test_context_socket (ZMQ_SERVER);
    test_getsockopt_thread_safe (server);
    test_context_socket_close (server);
}

int main (void)
{
    setup_test_environment ();

    // TODO this file could be merged with test_client_server
    UNITY_BEGIN ();
    RUN_TEST (test_client_getsockopt_thread_safe);
    RUN_TEST (test_server_getsockopt_thread_safe);
    RUN_TEST (test_thread_safe);

    return UNITY_END ();
}
