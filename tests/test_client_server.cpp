/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

SETUP_TEARDOWN_TESTCONTEXT

void create_inproc_client_server_pair (void **server_, void **client_)
{
    *server_ = test_context_socket (ZMQ_SERVER);
    *client_ = test_context_socket (ZMQ_CLIENT);

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_bind (*server_, "inproc://test-client-server"));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_connect (*client_, "inproc://test-client-server"));
}

void send_sndmore_expect_failure (void *socket_)
{
    int rc = zmq_send (socket_, "X", 1, ZMQ_SNDMORE);
    TEST_ASSERT_EQUAL_INT (-1, rc);
    TEST_ASSERT_EQUAL_INT (EINVAL, errno);
}

void test_client_sndmore_fails ()
{
    void *server, *client;
    create_inproc_client_server_pair (&server, &client);

    send_sndmore_expect_failure (client);

    test_context_socket_close (server);
    test_context_socket_close (client);
}

void test_server_sndmore_fails ()
{
    void *server, *client;
    create_inproc_client_server_pair (&server, &client);

    send_sndmore_expect_failure (server);

    test_context_socket_close (server);
    test_context_socket_close (client);
}

void test_routing_id ()
{
    void *server, *client;
    create_inproc_client_server_pair (&server, &client);

    send_string_expect_success (client, "X", 0);

    uint32_t routing_id;
    {
        zmq_msg_t msg;
        TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init (&msg));

        int rc = TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_recv (&msg, server, 0));
        TEST_ASSERT_EQUAL_INT (1, rc);

        routing_id = zmq_msg_routing_id (&msg);
        TEST_ASSERT_NOT_EQUAL (0, routing_id);

        TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg));
    }

    {
        zmq_msg_t msg;
        TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init_size (&msg, 1));

        char *data = static_cast<char *> (zmq_msg_data (&msg));
        data[0] = 2;

        TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_set_routing_id (&msg, routing_id));

        int rc = zmq_msg_send (&msg, server, 0);
        TEST_ASSERT_EQUAL_INT (1, rc);
    }

    {
        zmq_msg_t msg;
        TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init (&msg));

        int rc = zmq_msg_recv (&msg, client, 0);
        TEST_ASSERT_EQUAL_INT (1, rc);

        routing_id = zmq_msg_routing_id (&msg);
        TEST_ASSERT_EQUAL_UINT32 (0, routing_id);

        TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg));
    }

    test_context_socket_close (server);
    test_context_socket_close (client);
}

int main (void)
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_client_sndmore_fails);
    RUN_TEST (test_server_sndmore_fails);
    RUN_TEST (test_routing_id);
    return UNITY_END ();
}
