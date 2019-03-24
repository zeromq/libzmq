/*
    Copyright (c) 2007-2017 Contributors as noted in the AUTHORS file

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

#include <stdlib.h>

SETUP_TEARDOWN_TESTCONTEXT

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
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_proxy_steerable (frontend, backend, NULL, control));

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
    send_string_expect_success (control, "TERMINATE", 0);

    test_context_socket_close (publisher);
    test_context_socket_close (control);
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
