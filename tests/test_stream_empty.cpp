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

SETUP_TEARDOWN_TESTCONTEXT

void test_stream_empty ()
{
    char my_endpoint[MAX_SOCKET_STRING];

    void *stream = test_context_socket (ZMQ_STREAM);
    void *dealer = test_context_socket (ZMQ_DEALER);

    bind_loopback_ipv4 (stream, my_endpoint, sizeof my_endpoint);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (dealer, my_endpoint));
    send_string_expect_success (dealer, "", 0);

    zmq_msg_t ident, empty;
    zmq_msg_init (&ident);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_recv (&ident, stream, 0));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_msg_init_data (&empty, (void *) "", 0, NULL, NULL));

    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_send (&ident, stream, ZMQ_SNDMORE));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&ident));

    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_send (&empty, stream, 0));

    //  This close used to fail with Bad Address
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&empty));

    test_context_socket_close_zero_linger (dealer);
    test_context_socket_close_zero_linger (stream);
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_stream_empty);
    return UNITY_END ();
}
