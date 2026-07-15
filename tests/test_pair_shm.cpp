/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

void setUp ()
{
}

void tearDown ()
{
}

void test_pair_roundtrip_across_processes ()
{
    char endpoint[128];
    snprintf (endpoint, sizeof endpoint, "shm:///tmp/libzmq-shm-%d",
              static_cast<int> (getpid ()));

    void *server_ctx = zmq_ctx_new ();
    TEST_ASSERT_NOT_NULL (server_ctx);
    void *server = zmq_socket (server_ctx, ZMQ_PAIR);
    TEST_ASSERT_NOT_NULL (server);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (server, endpoint));

    const pid_t child = fork ();
    TEST_ASSERT_NOT_EQUAL (-1, child);
    if (child == 0) {
        void *client_ctx = zmq_ctx_new ();
        assert (client_ctx);
        void *client = zmq_socket (client_ctx, ZMQ_PAIR);
        assert (client);
        assert (zmq_connect (client, endpoint) == 0);
        assert (zmq_send (client, "pi", 2, ZMQ_SNDMORE) == 2);
        assert (zmq_send (client, "ng", 2, 0) == 2);
        char reply[4];
        assert (zmq_recv (client, reply, sizeof reply, 0) == 4);
        assert (memcmp (reply, "pong", 4) == 0);
        zmq_close (client);
        zmq_ctx_term (client_ctx);
        _exit (0);
    }

    char request[2];
    TEST_ASSERT_EQUAL_INT (2, zmq_recv (server, request, sizeof request, 0));
    TEST_ASSERT_EQUAL_MEMORY ("pi", request, 2);
    int more = 0;
    size_t more_size = sizeof more;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (server, ZMQ_RCVMORE, &more, &more_size));
    TEST_ASSERT_EQUAL_INT (1, more);
    TEST_ASSERT_EQUAL_INT (2, zmq_recv (server, request, sizeof request, 0));
    TEST_ASSERT_EQUAL_MEMORY ("ng", request, 2);
    TEST_ASSERT_EQUAL_INT (4, zmq_send (server, "pong", 4, 0));

    int status = 0;
    TEST_ASSERT_EQUAL (child, waitpid (child, &status, 0));
    TEST_ASSERT_TRUE (WIFEXITED (status));
    TEST_ASSERT_EQUAL_INT (0, WEXITSTATUS (status));
    zmq_close (server);
    zmq_ctx_term (server_ctx);
}

void test_pair_drains_shared_ring_before_peer_close ()
{
    char endpoint[128];
    snprintf (endpoint, sizeof endpoint, "shm:///tmp/libzmq-shm-drain-%d",
              static_cast<int> (getpid ()));

    void *server_ctx = zmq_ctx_new ();
    TEST_ASSERT_NOT_NULL (server_ctx);
    void *server = zmq_socket (server_ctx, ZMQ_PAIR);
    TEST_ASSERT_NOT_NULL (server);
    const int hwm = 1;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (server, ZMQ_RCVHWM, &hwm, sizeof hwm));
    const int timeout = 5000;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (server, ZMQ_RCVTIMEO, &timeout, sizeof timeout));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (server, endpoint));

    const pid_t child = fork ();
    TEST_ASSERT_NOT_EQUAL (-1, child);
    if (child == 0) {
        void *client_ctx = zmq_ctx_new ();
        assert (client_ctx);
        void *client = zmq_socket (client_ctx, ZMQ_PAIR);
        assert (client);
        assert (zmq_connect (client, endpoint) == 0);
        for (int i = 0; i != 64; ++i)
            assert (zmq_send (client, &i, sizeof i, 0) == sizeof i);
        zmq_close (client);
        zmq_ctx_term (client_ctx);
        _exit (0);
    }

    for (int i = 0; i != 55; ++i) {
        int value = -1;
        TEST_ASSERT_EQUAL_INT (sizeof value,
                               zmq_recv (server, &value, sizeof value, 0));
        TEST_ASSERT_EQUAL_INT (i, value);
    }

    int status = 0;
    TEST_ASSERT_EQUAL (child, waitpid (child, &status, 0));
    TEST_ASSERT_TRUE (WIFEXITED (status));
    TEST_ASSERT_EQUAL_INT (0, WEXITSTATUS (status));

    for (int i = 55; i != 64; ++i) {
        int value = -1;
        TEST_ASSERT_EQUAL_INT (sizeof value,
                               zmq_recv (server, &value, sizeof value, 0));
        TEST_ASSERT_EQUAL_INT (i, value);
    }
    zmq_close (server);
    zmq_ctx_term (server_ctx);
}

void test_pair_roundtrip_in_one_context ()
{
    char endpoint[128];
    snprintf (endpoint, sizeof endpoint, "shm:///tmp/libzmq-shm-context-%d",
              static_cast<int> (getpid ()));

    void *ctx = zmq_ctx_new ();
    TEST_ASSERT_NOT_NULL (ctx);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_ctx_set (ctx, ZMQ_IO_THREADS, 1));
    void *server = zmq_socket (ctx, ZMQ_PAIR);
    void *client = zmq_socket (ctx, ZMQ_PAIR);
    TEST_ASSERT_NOT_NULL (server);
    TEST_ASSERT_NOT_NULL (client);
    const int timeout = 5000;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (server, ZMQ_RCVTIMEO, &timeout, sizeof timeout));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (server, endpoint));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (client, endpoint));
    TEST_ASSERT_EQUAL_INT (4, zmq_send (client, "ping", 4, 0));
    char request[4];
    TEST_ASSERT_EQUAL_INT (4, zmq_recv (server, request, sizeof request, 0));
    TEST_ASSERT_EQUAL_MEMORY ("ping", request, 4);
    zmq_close (client);
    zmq_close (server);
    zmq_ctx_term (ctx);
}

void test_shm_rejects_unsupported_options ()
{
    char endpoint[128];
    snprintf (endpoint, sizeof endpoint, "shm:///tmp/libzmq-shm-secure-%d",
              static_cast<int> (getpid ()));

    void *ctx = zmq_ctx_new ();
    TEST_ASSERT_NOT_NULL (ctx);
    void *server = zmq_socket (ctx, ZMQ_PAIR);
    TEST_ASSERT_NOT_NULL (server);
    const int enabled = 1;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (server, ZMQ_PLAIN_SERVER, &enabled, sizeof enabled));
    TEST_ASSERT_FAILURE_ERRNO (ENOCOMPATPROTO, zmq_bind (server, endpoint));
    zmq_close (server);

    void *router = zmq_socket (ctx, ZMQ_ROUTER);
    TEST_ASSERT_NOT_NULL (router);
    TEST_ASSERT_FAILURE_ERRNO (ENOCOMPATPROTO, zmq_bind (router, endpoint));
    zmq_close (router);
    zmq_ctx_term (ctx);
}

int main ()
{
    setup_test_environment ();
    UNITY_BEGIN ();
    RUN_TEST (test_pair_roundtrip_across_processes);
    RUN_TEST (test_pair_drains_shared_ring_before_peer_close);
    RUN_TEST (test_pair_roundtrip_in_one_context);
    RUN_TEST (test_shm_rejects_unsupported_options);
    return UNITY_END ();
}
