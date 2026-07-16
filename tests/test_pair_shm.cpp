/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

#include <assert.h>
#include <new>
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

struct direct_payload_t
{
    explicit direct_payload_t (uint32_t value_) :
        magic (UINT32_C (0x53484d31)), value (value_)
    {
    }

    ~direct_payload_t () { ++*destruction_count (); }

    uint32_t *destruction_count ()
    {
        return reinterpret_cast<uint32_t *> (this + 1);
    }

    uint32_t magic;
    uint32_t value;
};

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

    for (int i = 0; i != 56; ++i) {
        int value = -1;
        TEST_ASSERT_EQUAL_INT (sizeof value,
                               zmq_recv (server, &value, sizeof value, 0));
        TEST_ASSERT_EQUAL_INT (i, value);
    }

    int status = 0;
    TEST_ASSERT_EQUAL (child, waitpid (child, &status, 0));
    TEST_ASSERT_TRUE (WIFEXITED (status));
    TEST_ASSERT_EQUAL_INT (0, WEXITSTATUS (status));

    for (int i = 56; i != 64; ++i) {
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
    zmq_msg_t direct_message;
    TEST_ASSERT_FAILURE_ERRNO (
      ENOTSUP,
      zmq_shm_msg_init (client, &direct_message, sizeof (uint32_t)));
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
    zmq_msg_t direct_message;
    TEST_ASSERT_FAILURE_ERRNO (
      ENOTSUP, zmq_shm_msg_init (router, &direct_message, sizeof (uint32_t)));
    TEST_ASSERT_FAILURE_ERRNO (ENOCOMPATPROTO, zmq_bind (router, endpoint));
    zmq_close (router);
    zmq_ctx_term (ctx);
}

void test_pair_direct_message_across_processes ()
{
    char endpoint[128];
    snprintf (endpoint, sizeof endpoint, "shm:///tmp/libzmq-shm-direct-%d",
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

        zmq_msg_t message;
        const size_t message_size =
          sizeof (direct_payload_t) + sizeof (uint32_t);
        while (zmq_shm_msg_init (client, &message, message_size) == -1) {
            assert (errno == EAGAIN);
            usleep (1000);
        }
        direct_payload_t *const payload =
          new (zmq_msg_data (&message)) direct_payload_t (42);
        *payload->destruction_count () = 0;
        assert (zmq_shm_msg_send (&message, client, 0)
                == static_cast<int> (message_size));
        assert (zmq_msg_close (&message) == 0);
        assert (zmq_send (client, "mixed", 5, ZMQ_DONTWAIT) == -1);
        assert (errno == ENOTSUP);

        char reply[4];
        assert (zmq_recv (client, reply, sizeof reply, 0) == 4);
        assert (memcmp (reply, "done", 4) == 0);
        zmq_close (client);
        zmq_ctx_term (client_ctx);
        _exit (0);
    }

    zmq_msg_t message;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init (&message));
    const size_t message_size =
      sizeof (direct_payload_t) + sizeof (uint32_t);
    TEST_ASSERT_EQUAL_INT (
      message_size, zmq_msg_recv (&message, server, 0));
    TEST_ASSERT_EQUAL_INT (1, zmq_msg_get (&message, ZMQ_SHM));
    direct_payload_t *const payload =
      static_cast<direct_payload_t *> (zmq_msg_data (&message));
    TEST_ASSERT_EQUAL_HEX32 (UINT32_C (0x53484d31), payload->magic);
    TEST_ASSERT_EQUAL_UINT32 (42, payload->value);
    uint32_t *const destruction_count = payload->destruction_count ();
    TEST_ASSERT_EQUAL_UINT32 (0, *destruction_count);
    payload->~direct_payload_t ();
    TEST_ASSERT_EQUAL_UINT32 (1, *destruction_count);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&message));
    TEST_ASSERT_EQUAL_INT (4, zmq_send (server, "done", 4, 0));

    int status = 0;
    TEST_ASSERT_EQUAL (child, waitpid (child, &status, 0));
    TEST_ASSERT_TRUE (WIFEXITED (status));
    TEST_ASSERT_EQUAL_INT (0, WEXITSTATUS (status));
    zmq_close (server);
    zmq_ctx_term (server_ctx);
}

void test_pair_direct_slot_released_on_message_close ()
{
    char endpoint[128];
    snprintf (endpoint, sizeof endpoint, "shm:///tmp/libzmq-shm-loan-%d",
              static_cast<int> (getpid ()));

    int full_pipe[2];
    int released_pipe[2];
    TEST_ASSERT_SUCCESS_ERRNO (pipe (full_pipe));
    TEST_ASSERT_SUCCESS_ERRNO (pipe (released_pipe));

    void *server_ctx = zmq_ctx_new ();
    TEST_ASSERT_NOT_NULL (server_ctx);
    void *server = zmq_socket (server_ctx, ZMQ_PAIR);
    TEST_ASSERT_NOT_NULL (server);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (server, endpoint));

    const pid_t child = fork ();
    TEST_ASSERT_NOT_EQUAL (-1, child);
    if (child == 0) {
        close (full_pipe[0]);
        close (released_pipe[1]);
        void *client_ctx = zmq_ctx_new ();
        assert (client_ctx);
        void *client = zmq_socket (client_ctx, ZMQ_PAIR);
        assert (client);
        assert (zmq_connect (client, endpoint) == 0);

        zmq_msg_t original;
        while (zmq_shm_msg_init (client, &original, sizeof (uint32_t)) == -1) {
            assert (errno == EAGAIN);
            usleep (1000);
        }
        *static_cast<uint32_t *> (zmq_msg_data (&original)) = 99;
        zmq_msg_t alias;
        assert (zmq_msg_init (&alias) == 0);
        assert (zmq_msg_copy (&alias, &original) == 0);
        assert (zmq_shm_msg_send (&original, client, 0) == -1);
        assert (errno == EINVAL);
        assert (zmq_msg_close (&alias) == 0);
        assert (zmq_msg_close (&original) == 0);

        for (uint32_t i = 0; i != 8; ++i) {
            zmq_msg_t message;
            while (zmq_shm_msg_init (client, &message, sizeof i) == -1) {
                assert (errno == EAGAIN);
                usleep (1000);
            }
            *static_cast<uint32_t *> (zmq_msg_data (&message)) = i;
            assert (zmq_shm_msg_send (&message, client, 0) == sizeof i);
            assert (zmq_msg_close (&message) == 0);
        }

        zmq_msg_t ninth;
        assert (zmq_shm_msg_init (client, &ninth, sizeof (uint32_t)) == -1);
        assert (errno == EAGAIN);
        const unsigned char marker = 1;
        assert (write (full_pipe[1], &marker, sizeof marker)
                == static_cast<ssize_t> (sizeof marker));
        unsigned char released = 0;
        assert (read (released_pipe[0], &released, sizeof released)
                == static_cast<ssize_t> (sizeof released));
        assert (released == marker);
        assert (zmq_shm_msg_init (client, &ninth, sizeof (uint32_t)) == -1);
        assert (errno == EAGAIN);
        assert (write (full_pipe[1], &marker, sizeof marker)
                == static_cast<ssize_t> (sizeof marker));
        assert (read (released_pipe[0], &released, sizeof released)
                == static_cast<ssize_t> (sizeof released));
        assert (released == marker);

        while (zmq_shm_msg_init (client, &ninth, sizeof (uint32_t)) == -1) {
            assert (errno == EAGAIN);
            usleep (1000);
        }
        *static_cast<uint32_t *> (zmq_msg_data (&ninth)) = 8;
        assert (zmq_shm_msg_send (&ninth, client, 0) == sizeof (uint32_t));
        assert (zmq_msg_close (&ninth) == 0);

        close (full_pipe[1]);
        close (released_pipe[0]);
        zmq_close (client);
        zmq_ctx_term (client_ctx);
        _exit (0);
    }

    close (full_pipe[1]);
    close (released_pipe[0]);
    zmq_msg_t messages[8];
    for (uint32_t i = 0; i != 8; ++i) {
        TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init (&messages[i]));
        TEST_ASSERT_EQUAL_INT (
          sizeof (uint32_t), zmq_msg_recv (&messages[i], server, 0));
        TEST_ASSERT_EQUAL_INT (1, zmq_msg_get (&messages[i], ZMQ_SHM));
        TEST_ASSERT_EQUAL_UINT32 (
          i, *static_cast<uint32_t *> (zmq_msg_data (&messages[i])));
    }
    zmq_msg_t first_alias;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init (&first_alias));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_copy (&first_alias, &messages[0]));

    unsigned char marker = 0;
    TEST_ASSERT_EQUAL_INT (
      sizeof marker, read (full_pipe[0], &marker, sizeof marker));
    TEST_ASSERT_EQUAL_UINT8 (1, marker);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&messages[0]));
    TEST_ASSERT_EQUAL_INT (
      sizeof marker, write (released_pipe[1], &marker, sizeof marker));
    TEST_ASSERT_EQUAL_INT (
      sizeof marker, read (full_pipe[0], &marker, sizeof marker));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&first_alias));
    TEST_ASSERT_EQUAL_INT (
      sizeof marker, write (released_pipe[1], &marker, sizeof marker));

    zmq_msg_t ninth;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init (&ninth));
    TEST_ASSERT_EQUAL_INT (
      sizeof (uint32_t), zmq_msg_recv (&ninth, server, 0));
    TEST_ASSERT_EQUAL_INT (1, zmq_msg_get (&ninth, ZMQ_SHM));
    TEST_ASSERT_EQUAL_UINT32 (
      8, *static_cast<uint32_t *> (zmq_msg_data (&ninth)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&ninth));
    for (size_t i = 1; i != 8; ++i)
        TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&messages[i]));

    close (full_pipe[0]);
    close (released_pipe[1]);
    int status = 0;
    TEST_ASSERT_EQUAL (child, waitpid (child, &status, 0));
    TEST_ASSERT_TRUE (WIFEXITED (status));
    TEST_ASSERT_EQUAL_INT (0, WEXITSTATUS (status));
    zmq_close (server);
    zmq_ctx_term (server_ctx);
}

void test_pair_direct_message_outlives_socket_and_context ()
{
    char endpoint[128];
    snprintf (endpoint, sizeof endpoint, "shm:///tmp/libzmq-shm-outlive-%d",
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

        zmq_msg_t message;
        const size_t message_size =
          sizeof (direct_payload_t) + sizeof (uint32_t);
        while (zmq_shm_msg_init (client, &message, message_size) == -1) {
            assert (errno == EAGAIN);
            usleep (1000);
        }
        direct_payload_t *const payload =
          new (zmq_msg_data (&message)) direct_payload_t (77);
        *payload->destruction_count () = 0;
        assert (zmq_shm_msg_send (&message, client, 0)
                == static_cast<int> (message_size));
        assert (zmq_msg_close (&message) == 0);
        zmq_close (client);
        zmq_ctx_term (client_ctx);
        _exit (0);
    }

    zmq_msg_t message;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init (&message));
    const size_t message_size =
      sizeof (direct_payload_t) + sizeof (uint32_t);
    TEST_ASSERT_EQUAL_INT (
      message_size, zmq_msg_recv (&message, server, 0));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_close (server));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_ctx_term (server_ctx));

    TEST_ASSERT_EQUAL_INT (1, zmq_msg_get (&message, ZMQ_SHM));
    direct_payload_t *const payload =
      static_cast<direct_payload_t *> (zmq_msg_data (&message));
    TEST_ASSERT_EQUAL_HEX32 (UINT32_C (0x53484d31), payload->magic);
    TEST_ASSERT_EQUAL_UINT32 (77, payload->value);
    uint32_t *const destruction_count = payload->destruction_count ();
    TEST_ASSERT_EQUAL_UINT32 (0, *destruction_count);
    payload->~direct_payload_t ();
    TEST_ASSERT_EQUAL_UINT32 (1, *destruction_count);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&message));

    int status = 0;
    TEST_ASSERT_EQUAL (child, waitpid (child, &status, 0));
    TEST_ASSERT_TRUE (WIFEXITED (status));
    TEST_ASSERT_EQUAL_INT (0, WEXITSTATUS (status));
}

int main ()
{
    setup_test_environment ();
    UNITY_BEGIN ();
    RUN_TEST (test_pair_roundtrip_across_processes);
    RUN_TEST (test_pair_drains_shared_ring_before_peer_close);
    RUN_TEST (test_pair_roundtrip_in_one_context);
    RUN_TEST (test_shm_rejects_unsupported_options);
    RUN_TEST (test_pair_direct_message_across_processes);
    RUN_TEST (test_pair_direct_slot_released_on_message_close);
    RUN_TEST (test_pair_direct_message_outlives_socket_and_context);
    return UNITY_END ();
}
