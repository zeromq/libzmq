/* SPDX-License-Identifier: MPL-2.0 */

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
