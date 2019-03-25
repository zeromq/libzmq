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
    TEST_ASSERT_SUCCESS_ERRNO (zmq_proxy_steerable (rep, rep, NULL, control));

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

    send_string_expect_success (control, "TERMINATE", 0);

    test_context_socket_close (control);
    test_context_socket_close (req);
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
