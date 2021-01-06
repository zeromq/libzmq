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

#include <string.h>

SETUP_TEARDOWN_TESTCONTEXT

void test_setsockopt_tcp_recv_buffer ()
{
    void *socket = test_context_socket (ZMQ_PUSH);

    int val = 0;
    size_t placeholder = sizeof (val);

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (socket, ZMQ_RCVBUF, &val, &placeholder));
    TEST_ASSERT_EQUAL_INT (-1, val);

    val = 16384;

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (socket, ZMQ_RCVBUF, &val, sizeof (val)));
    TEST_ASSERT_EQUAL_INT (16384, val);

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (socket, ZMQ_RCVBUF, &val, &placeholder));
    TEST_ASSERT_EQUAL_INT (16384, val);

    test_context_socket_close (socket);
}

void test_setsockopt_tcp_send_buffer ()
{
    void *socket = test_context_socket (ZMQ_PUSH);

    int val = 0;
    size_t placeholder = sizeof (val);

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (socket, ZMQ_SNDBUF, &val, &placeholder));
    TEST_ASSERT_EQUAL_INT (-1, val);

    val = 16384;

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (socket, ZMQ_SNDBUF, &val, sizeof (val)));
    TEST_ASSERT_EQUAL_INT (16384, val);

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (socket, ZMQ_SNDBUF, &val, &placeholder));
    TEST_ASSERT_EQUAL_INT (16384, val);

    test_context_socket_close (socket);
}

void test_setsockopt_use_fd ()
{
    void *socket = test_context_socket (ZMQ_PUSH);

    int val = 0;
    size_t placeholder = sizeof (val);

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (socket, ZMQ_USE_FD, &val, &placeholder));
    TEST_ASSERT_EQUAL_INT (-1, val);

    val = 3;

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (socket, ZMQ_USE_FD, &val, sizeof (val)));
    TEST_ASSERT_EQUAL_INT (3, val);

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (socket, ZMQ_USE_FD, &val, &placeholder));
    TEST_ASSERT_EQUAL_INT (3, val);

    test_context_socket_close (socket);
}

#define BOUNDDEVBUFSZ 16
void test_setsockopt_bindtodevice ()
{
    void *socket = test_context_socket (ZMQ_PUSH);

#ifdef ZMQ_BINDTODEVICE
    char devname[BOUNDDEVBUFSZ];
    size_t buflen = BOUNDDEVBUFSZ;

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (socket, ZMQ_BINDTODEVICE, devname, &buflen));
    TEST_ASSERT_EQUAL_INT8 ('\0', devname[0]);
    TEST_ASSERT_EQUAL_UINT (1, buflen);

    sprintf (devname, "testdev");
    buflen = strlen (devname);

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (socket, ZMQ_BINDTODEVICE, devname, buflen));

    buflen = BOUNDDEVBUFSZ;
    memset (devname, 0, buflen);

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (socket, ZMQ_BINDTODEVICE, devname, &buflen));
    TEST_ASSERT_EQUAL_STRING_LEN ("testdev", devname, buflen);
#endif

    test_context_socket_close (socket);
}

void test_setsockopt_priority ()
{
#ifdef ZMQ_BUILD_DRAFT_API
#ifdef ZMQ_HAVE_SO_PRIORITY
    void *socket = test_context_socket (ZMQ_PUSH);

    int val = 5;
    size_t placeholder = sizeof (val);

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (socket, ZMQ_PRIORITY, &val, &placeholder));
    TEST_ASSERT_EQUAL_INT (0, val);

    val = 3;

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (socket, ZMQ_PRIORITY, &val, sizeof (val)));
    TEST_ASSERT_EQUAL_INT (3, val);

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (socket, ZMQ_PRIORITY, &val, &placeholder));
    TEST_ASSERT_EQUAL_INT (3, val);

    test_context_socket_close (socket);
#else
    TEST_IGNORE_MESSAGE ("libzmq without ZMQ_PRIORITY support, "
                         "ignoring setsockopt_priority test");
#endif
#else
    TEST_IGNORE_MESSAGE ("libzmq without DRAFT support, ignoring "
                         "setsockopt_priority test");
#endif
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_setsockopt_tcp_recv_buffer);
    RUN_TEST (test_setsockopt_tcp_send_buffer);
    RUN_TEST (test_setsockopt_use_fd);
    RUN_TEST (test_setsockopt_bindtodevice);
    RUN_TEST (test_setsockopt_priority);
    return UNITY_END ();
}
