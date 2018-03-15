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

static void receiver (void *socket)
{
    char buffer[16];
    int rc = zmq_recv (socket, &buffer, sizeof (buffer), 0);
    assert (rc == -1);
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

int main (void)
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_ctx_destroy);
    RUN_TEST (test_ctx_shutdown);
    RUN_TEST (test_zmq_ctx_term_null_fails);
    RUN_TEST (test_zmq_term_null_fails);
    RUN_TEST (test_zmq_ctx_shutdown_null_fails);
    return UNITY_END ();
}
