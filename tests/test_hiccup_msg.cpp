/*
    Copyright (c) 2007-2021 Contributors as noted in the AUTHORS file

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

SETUP_TEARDOWN_TESTCONTEXT

void test ()
{
    char address[MAX_SOCKET_STRING];
    size_t addr_length = sizeof (address);

    //  Create a server
    void *server = test_context_socket (ZMQ_SERVER);

    //  bind server
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (server, "tcp://127.0.0.1:*"));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (server, ZMQ_LAST_ENDPOINT, address, &addr_length));

    //  Create a client
    void *client = test_context_socket (ZMQ_CLIENT);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (client, ZMQ_HELLO_MSG, "HELLO", 5));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (client, ZMQ_HICCUP_MSG, "HICCUP", 6));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (client, address));

    // Receive the hello message from client
    recv_string_expect_success (server, "HELLO", 0);

    // Kill the server
    test_context_socket_close (server);

    // Receive the hiccup message
    recv_string_expect_success (client, "HICCUP", 0);

    //  Clean up.
    test_context_socket_close (client);
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test);
    return UNITY_END ();
}
