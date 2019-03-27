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

#include <string.h>

#if defined _WIN32
#include "../src/windows.hpp"
#endif

SETUP_TEARDOWN_TESTCONTEXT

typedef void (*extra_func_t) (void *socket_);

#ifdef ZMQ_BUILD_DRAFT
void set_sockopt_fastpath (void *socket)
{
    int value = 1;
    int rc =
      zmq_setsockopt (socket, ZMQ_LOOPBACK_FASTPATH, &value, sizeof value);
    assert (rc == 0);
}
#endif

void test_pair_tcp (extra_func_t extra_func_ = NULL)
{
    void *sb = test_context_socket (ZMQ_PAIR);

    if (extra_func_)
        extra_func_ (sb);

    char my_endpoint[MAX_SOCKET_STRING];
    bind_loopback_ipv4 (sb, my_endpoint, sizeof my_endpoint);

    void *sc = test_context_socket (ZMQ_PAIR);
    if (extra_func_)
        extra_func_ (sc);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc, my_endpoint));

    bounce (sb, sc);

    test_context_socket_close (sc);
    test_context_socket_close (sb);
}

void test_pair_tcp_regular ()
{
    test_pair_tcp ();
}

void test_pair_tcp_connect_by_name ()
{
    // all other tcp test cases bind to a loopback wildcard address, then
    // retrieve the bound endpoint, which is numerical, and use that to
    // connect. this test cases specifically uses "localhost" to connect
    // to ensure that names are correctly resolved
    void *sb = test_context_socket (ZMQ_PAIR);

    char bound_endpoint[MAX_SOCKET_STRING];
    bind_loopback_ipv4 (sb, bound_endpoint, sizeof bound_endpoint);

    // extract the bound port number
    const char *pos = strrchr (bound_endpoint, ':');
    TEST_ASSERT_NOT_NULL (pos);
    const char connect_endpoint_prefix[] = "tcp://localhost";
    char connect_endpoint[MAX_SOCKET_STRING];
    strcpy (connect_endpoint, connect_endpoint_prefix);
    strcat (connect_endpoint, pos);

    void *sc = test_context_socket (ZMQ_PAIR);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc, connect_endpoint));

    bounce (sb, sc);

    test_context_socket_close (sc);
    test_context_socket_close (sb);
}


#ifdef ZMQ_BUILD_DRAFT
void test_pair_tcp_fastpath ()
{
    test_pair_tcp (set_sockopt_fastpath);
}
#endif

#ifdef _WIN32
void test_io_completion_port ()
{
    void *const s = test_context_socket (ZMQ_PAIR);
    SOCKET fd;
    size_t fd_size = sizeof fd;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_getsockopt (s, ZMQ_FD, &fd, &fd_size));

    ::WSAPROTOCOL_INFO pi;
    TEST_ASSERT_SUCCESS_RAW_ERRNO (
      ::WSADuplicateSocket (fd, ::GetCurrentProcessId (), &pi));
    const SOCKET socket = ::WSASocket (pi.iAddressFamily /*AF_INET*/,
                                       pi.iSocketType /*SOCK_STREAM*/,
                                       pi.iProtocol /*IPPROTO_TCP*/, &pi, 0, 0);

    const HANDLE iocp =
      ::CreateIoCompletionPort (INVALID_HANDLE_VALUE, NULL, 0, 0);
    TEST_ASSERT_NOT_EQUAL (NULL, iocp);
    const HANDLE res =
      ::CreateIoCompletionPort (reinterpret_cast<HANDLE> (socket), iocp, 0, 0);
    TEST_ASSERT_NOT_EQUAL (NULL, res);

    TEST_ASSERT_SUCCESS_RAW_ERRNO (closesocket (socket));
    TEST_ASSERT_TRUE (CloseHandle (iocp));

    test_context_socket_close (s);
}
#endif

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_pair_tcp_regular);
    RUN_TEST (test_pair_tcp_connect_by_name);
#ifdef ZMQ_BUILD_DRAFT
    RUN_TEST (test_pair_tcp_fastpath);
#endif
#ifdef _WIN32
    RUN_TEST (test_io_completion_port);
#endif

    return UNITY_END ();
}
