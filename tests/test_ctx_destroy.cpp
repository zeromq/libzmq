/*
    Copyright (c) 2007-2016 Contributors as noted in the AUTHORS file

    This file is part of libzmq, the ZeroMQ core engine in C++.

    libzmq is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License (LGPL) as published
    by the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    As a special exception, the Contributors give you permission to link
    this library with independent modules to produce an executable,
    regardless of the license terms of these independent modules, and to
    copy and distribute the resulting executable under terms of your choice,
    provided that you also meet, for each linked independent module, the
    terms and conditions of the license of that module. An independent
    module is a module which is not derived from or based on this library.
    If you modify this library, you must extend this exception to your
    version of the library.

    libzmq is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
    FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
    License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "testutil.hpp"
#include "testutil_unity.hpp"

#include <unity.h>

void setUp ()
{
}

void tearDown ()
{
}

static void receiver (void *socket_)
{
    char buffer[16];
    int rc = zmq_recv (socket_, &buffer, sizeof (buffer), 0);
    // TODO which error is expected here? use TEST_ASSERT_FAILURE_ERRNO instead
    TEST_ASSERT_EQUAL_INT (-1, rc);
}

void test_ctx_destroy ()
{
    //  Set up our context and sockets
    void *ctx = zmq_ctx_new ();
    TEST_ASSERT_NOT_NULL (ctx);

    void *socket = zmq_socket (ctx, ZMQ_PULL);
    TEST_ASSERT_NOT_NULL (socket);

    // Close the socket
    TEST_ASSERT_SUCCESS_ERRNO (zmq_close (socket));

    // Destroy the context
    TEST_ASSERT_SUCCESS_ERRNO (zmq_ctx_destroy (ctx));
}

void test_ctx_shutdown ()
{
    //  Set up our context and sockets
    void *ctx = zmq_ctx_new ();
    TEST_ASSERT_NOT_NULL (ctx);

    void *socket = zmq_socket (ctx, ZMQ_PULL);
    TEST_ASSERT_NOT_NULL (socket);

    // Spawn a thread to receive on socket
    void *receiver_thread = zmq_threadstart (&receiver, socket);

    // Wait for thread to start up and block
    msleep (SETTLE_TIME);

    // Shutdown context, if we used destroy here we would deadlock.
    TEST_ASSERT_SUCCESS_ERRNO (zmq_ctx_shutdown (ctx));

    // Wait for thread to finish
    zmq_threadclose (receiver_thread);

    // Close the socket.
    TEST_ASSERT_SUCCESS_ERRNO (zmq_close (socket));

    // Destory the context, will now not hang as we have closed the socket.
    TEST_ASSERT_SUCCESS_ERRNO (zmq_ctx_destroy (ctx));
}

void test_zmq_ctx_term_null_fails ()
{
    int rc = zmq_ctx_term (NULL);
    TEST_ASSERT_EQUAL_INT (-1, rc);
    TEST_ASSERT_EQUAL_INT (EFAULT, errno);
}

void test_zmq_term_null_fails ()
{
    int rc = zmq_term (NULL);
    TEST_ASSERT_EQUAL_INT (-1, rc);
    TEST_ASSERT_EQUAL_INT (EFAULT, errno);
}

void test_zmq_ctx_shutdown_null_fails ()
{
    int rc = zmq_ctx_shutdown (NULL);
    TEST_ASSERT_EQUAL_INT (-1, rc);
    TEST_ASSERT_EQUAL_INT (EFAULT, errno);
}

#ifdef ZMQ_HAVE_POLLER
struct poller_test_data_t
{
    int socket_type;
    void *ctx;
    void *counter;
};

void run_poller (void *data_)
{
    struct poller_test_data_t *poller_test_data =
      (struct poller_test_data_t *) data_;

    void *socket =
      zmq_socket (poller_test_data->ctx, poller_test_data->socket_type);
    TEST_ASSERT_NOT_NULL (socket);

    void *poller = zmq_poller_new ();
    TEST_ASSERT_NOT_NULL (poller);

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_poller_add (poller, socket, NULL, ZMQ_POLLIN));

    zmq_atomic_counter_set (poller_test_data->counter, 1);

    zmq_poller_event_t event;
    TEST_ASSERT_FAILURE_ERRNO (ETERM, zmq_poller_wait (poller, &event, -1));

    TEST_ASSERT_SUCCESS_ERRNO (zmq_poller_destroy (&poller));

    // Close the socket
    TEST_ASSERT_SUCCESS_ERRNO (zmq_close (socket));
}
#endif

void test_poller_exists_with_socket_on_zmq_ctx_term (const int socket_type_)
{
#ifdef ZMQ_HAVE_POLLER
    struct poller_test_data_t poller_test_data;

    poller_test_data.socket_type = socket_type_;

    //  Set up our context and sockets
    poller_test_data.ctx = zmq_ctx_new ();
    TEST_ASSERT_NOT_NULL (poller_test_data.ctx);

    poller_test_data.counter = zmq_atomic_counter_new ();
    TEST_ASSERT_NOT_NULL (poller_test_data.counter);

    void *thread = zmq_threadstart (run_poller, &poller_test_data);
    TEST_ASSERT_NOT_NULL (thread);

    while (zmq_atomic_counter_value (poller_test_data.counter) == 0) {
        msleep (10);
    }

    // Destroy the context
    TEST_ASSERT_SUCCESS_ERRNO (zmq_ctx_destroy (poller_test_data.ctx));

    zmq_threadclose (thread);

    zmq_atomic_counter_destroy (&poller_test_data.counter);
#else
    TEST_IGNORE_MESSAGE ("libzmq without zmq_poller_* support, ignoring test");
#endif
}

void test_poller_exists_with_socket_on_zmq_ctx_term_thread_safe_socket ()
{
#ifdef ZMQ_BUILD_DRAFT_API
    test_poller_exists_with_socket_on_zmq_ctx_term (ZMQ_CLIENT);
#else
    TEST_IGNORE_MESSAGE ("libzmq without DRAFT support, ignoring test");
#endif
}

void test_poller_exists_with_socket_on_zmq_ctx_term_non_thread_safe_socket ()
{
    test_poller_exists_with_socket_on_zmq_ctx_term (ZMQ_DEALER);
}

int main (void)
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_ctx_destroy);
    RUN_TEST (test_ctx_shutdown);
    RUN_TEST (test_zmq_ctx_term_null_fails);
    RUN_TEST (test_zmq_term_null_fails);
    RUN_TEST (test_zmq_ctx_shutdown_null_fails);

    RUN_TEST (
      test_poller_exists_with_socket_on_zmq_ctx_term_non_thread_safe_socket);
    RUN_TEST (
      test_poller_exists_with_socket_on_zmq_ctx_term_thread_safe_socket);

    return UNITY_END ();
}
