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

SETUP_TEARDOWN_TESTCONTEXT

void test_scatter_gather_multipart_fails ()
{
    void *scatter = test_context_socket (ZMQ_SCATTER);
    void *gather = test_context_socket (ZMQ_GATHER);

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_bind (scatter, "inproc://test-scatter-gather"));

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_connect (gather, "inproc://test-scatter-gather"));

    //  Should fail, multipart is not supported
    TEST_ASSERT_FAILURE_ERRNO (EINVAL,
                               zmq_send_const (scatter, "1", 1, ZMQ_SNDMORE));

    test_context_socket_close (scatter);
    test_context_socket_close (gather);
}

void test_scatter_gather ()
{
    void *scatter = test_context_socket (ZMQ_SCATTER);
    void *gather = test_context_socket (ZMQ_GATHER);
    void *gather2 = test_context_socket (ZMQ_GATHER);

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_bind (scatter, "inproc://test-scatter-gather"));

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_connect (gather, "inproc://test-scatter-gather"));

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_connect (gather2, "inproc://test-scatter-gather"));

    send_string_expect_success (scatter, "1", 0);
    send_string_expect_success (scatter, "2", 0);

    recv_string_expect_success (gather, "1", 0);
    recv_string_expect_success (gather2, "2", 0);

    test_context_socket_close (scatter);
    test_context_socket_close (gather);
    test_context_socket_close (gather2);
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_scatter_gather);
    RUN_TEST (test_scatter_gather_multipart_fails);
    return UNITY_END ();
}
