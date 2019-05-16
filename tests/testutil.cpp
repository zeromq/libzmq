/*
    Copyright (c) 2007-2019 Contributors as noted in the AUTHORS file

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

#include <stdarg.h>
#include <string.h>

#if defined _WIN32
#include "../src/windows.hpp"
#if defined _MSC_VER
#include <crtdbg.h>
#pragma warning(disable : 4996)
// iphlpapi is needed for if_nametoindex (not on Windows XP)
#if !defined ZMQ_HAVE_WINDOWS_TARGET_XP
#pragma comment(lib, "iphlpapi")
#endif
#endif
#else
#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <grp.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>
#if defined(ZMQ_HAVE_AIX)
#include <sys/types.h>
#include <sys/socketvar.h>
#endif
#endif

const char *SEQ_END = (const char *) 1;

const char bounce_content[] = "12345678ABCDEFGH12345678abcdefgh";

static void send_bounce_msg (void *socket_)
{
    send_string_expect_success (socket_, bounce_content, ZMQ_SNDMORE);
    send_string_expect_success (socket_, bounce_content, 0);
}

static void recv_bounce_msg (void *socket_)
{
    recv_string_expect_success (socket_, bounce_content, 0);
    int rcvmore;
    size_t sz = sizeof (rcvmore);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (socket_, ZMQ_RCVMORE, &rcvmore, &sz));
    TEST_ASSERT_TRUE (rcvmore);
    recv_string_expect_success (socket_, bounce_content, 0);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (socket_, ZMQ_RCVMORE, &rcvmore, &sz));
    TEST_ASSERT_FALSE (rcvmore);
}

void bounce (void *server_, void *client_)
{
    //  Send message from client to server
    send_bounce_msg (client_);

    //  Receive message at server side and
    //  check that message is still the same
    recv_bounce_msg (server_);

    //  Send two parts back to client
    send_bounce_msg (server_);

    //  Receive the two parts at the client side
    recv_bounce_msg (client_);
}

static void send_bounce_msg_may_fail (void *socket_)
{
    int timeout = 250;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (socket_, ZMQ_SNDTIMEO, &timeout, sizeof (int)));
    int rc = zmq_send (socket_, bounce_content, 32, ZMQ_SNDMORE);
    TEST_ASSERT_TRUE ((rc == 32) || ((rc == -1) && (errno == EAGAIN)));
    rc = zmq_send (socket_, bounce_content, 32, 0);
    TEST_ASSERT_TRUE ((rc == 32) || ((rc == -1) && (errno == EAGAIN)));
}

static void recv_bounce_msg_fail (void *socket_)
{
    int timeout = 250;
    char buffer[32];
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (socket_, ZMQ_RCVTIMEO, &timeout, sizeof (int)));
    TEST_ASSERT_FAILURE_ERRNO (EAGAIN, zmq_recv (socket_, buffer, 32, 0));
}

void expect_bounce_fail (void *server_, void *client_)
{
    //  Send message from client to server
    send_bounce_msg_may_fail (client_);

    //  Receive message at server side (should not succeed)
    recv_bounce_msg_fail (server_);

    //  Send message from server to client to test other direction
    //  If connection failed, send may block, without a timeout
    send_bounce_msg_may_fail (server_);

    //  Receive message at client side (should not succeed)
    recv_bounce_msg_fail (client_);
}

char *s_recv (void *socket_)
{
    char buffer[256];
    int size = zmq_recv (socket_, buffer, 255, 0);
    if (size == -1)
        return NULL;
    if (size > 255)
        size = 255;
    buffer[size] = 0;
    return strdup (buffer);
}

void s_send_seq (void *socket_, ...)
{
    va_list ap;
    va_start (ap, socket_);
    const char *data = va_arg (ap, const char *);
    while (true) {
        const char *prev = data;
        data = va_arg (ap, const char *);
        bool end = data == SEQ_END;

        if (!prev) {
            TEST_ASSERT_SUCCESS_ERRNO (
              zmq_send (socket_, 0, 0, end ? 0 : ZMQ_SNDMORE));
        } else {
            TEST_ASSERT_SUCCESS_ERRNO (zmq_send (
              socket_, prev, strlen (prev) + 1, end ? 0 : ZMQ_SNDMORE));
        }
        if (end)
            break;
    }
    va_end (ap);
}

void s_recv_seq (void *socket_, ...)
{
    zmq_msg_t msg;
    zmq_msg_init (&msg);

    int more;
    size_t more_size = sizeof (more);

    va_list ap;
    va_start (ap, socket_);
    const char *data = va_arg (ap, const char *);

    while (true) {
        TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_recv (&msg, socket_, 0));

        if (!data)
            TEST_ASSERT_EQUAL_INT (0, zmq_msg_size (&msg));
        else
            TEST_ASSERT_EQUAL_STRING (data, (const char *) zmq_msg_data (&msg));

        data = va_arg (ap, const char *);
        bool end = data == SEQ_END;

        TEST_ASSERT_SUCCESS_ERRNO (
          zmq_getsockopt (socket_, ZMQ_RCVMORE, &more, &more_size));

        TEST_ASSERT_TRUE (!more == end);
        if (end)
            break;
    }
    va_end (ap);

    zmq_msg_close (&msg);
}

void close_zero_linger (void *socket_)
{
    int linger = 0;
    int rc = zmq_setsockopt (socket_, ZMQ_LINGER, &linger, sizeof (linger));
    TEST_ASSERT_TRUE (rc == 0 || errno == ETERM);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_close (socket_));
}

void setup_test_environment ()
{
#if defined _WIN32
#if defined _MSC_VER
    _set_abort_behavior (0, _WRITE_ABORT_MSG);
    _CrtSetReportMode (_CRT_ASSERT, _CRTDBG_MODE_FILE);
    _CrtSetReportFile (_CRT_ASSERT, _CRTDBG_FILE_STDERR);
#endif
#else
#if defined ZMQ_HAVE_CYGWIN
    // abort test after 121 seconds
    alarm (121);
#else
#if !defined ZMQ_DISABLE_TEST_TIMEOUT
    // abort test after 60 seconds
    alarm (60);
#endif
#endif
#endif
#if defined __MVS__
    // z/OS UNIX System Services: Ignore SIGPIPE during test runs, as a
    // workaround for no SO_NOGSIGPIPE socket option.
    signal (SIGPIPE, SIG_IGN);
#endif
}

void msleep (int milliseconds_)
{
#ifdef ZMQ_HAVE_WINDOWS
    Sleep (milliseconds_);
#else
    usleep (static_cast<useconds_t> (milliseconds_) * 1000);
#endif
}

int is_ipv6_available ()
{
#if defined(ZMQ_HAVE_WINDOWS) && (_WIN32_WINNT < 0x0600)
    return 0;
#else
    int rc, ipv6 = 1;
    struct sockaddr_in6 test_addr;

    memset (&test_addr, 0, sizeof (test_addr));
    test_addr.sin6_family = AF_INET6;
    inet_pton (AF_INET6, "::1", &(test_addr.sin6_addr));

    fd_t fd = socket (AF_INET6, SOCK_STREAM, IPPROTO_IP);
    if (fd == retired_fd)
        ipv6 = 0;
    else {
#ifdef ZMQ_HAVE_WINDOWS
        setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, (const char *) &ipv6,
                    sizeof (int));
        rc = setsockopt (fd, IPPROTO_IPV6, IPV6_V6ONLY, (const char *) &ipv6,
                         sizeof (int));
        if (rc == SOCKET_ERROR)
            ipv6 = 0;
        else {
            rc = bind (fd, (struct sockaddr *) &test_addr, sizeof (test_addr));
            if (rc == SOCKET_ERROR)
                ipv6 = 0;
        }
#else
        setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &ipv6, sizeof (int));
        rc = setsockopt (fd, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6, sizeof (int));
        if (rc != 0)
            ipv6 = 0;
        else {
            rc = bind (fd, (struct sockaddr *) &test_addr, sizeof (test_addr));
            if (rc != 0)
                ipv6 = 0;
        }
#endif
        close (fd);
    }

    return ipv6;
#endif // _WIN32_WINNT < 0x0600
}

int is_tipc_available ()
{
#ifndef ZMQ_HAVE_TIPC
    return 0;
#else
    int tipc = 0;

    void *ctx = zmq_init (1);
    TEST_ASSERT_NOT_NULL (ctx);
    void *rep = zmq_socket (ctx, ZMQ_REP);
    TEST_ASSERT_NOT_NULL (rep);
    tipc = zmq_bind (rep, "tipc://{5560,0,0}");

    zmq_close (rep);
    zmq_ctx_term (ctx);

    return tipc == 0;
#endif // ZMQ_HAVE_TIPC
}

int test_inet_pton (int af_, const char *src_, void *dst_)
{
#if defined(ZMQ_HAVE_WINDOWS) && (_WIN32_WINNT < 0x0600)
    if (af_ == AF_INET) {
        struct in_addr *ip4addr = (struct in_addr *) dst_;

        ip4addr->s_addr = inet_addr (src_);

        //  INADDR_NONE is -1 which is also a valid representation for IP
        //  255.255.255.255
        if (ip4addr->s_addr == INADDR_NONE
            && strcmp (src_, "255.255.255.255") != 0) {
            return 0;
        }

        //  Success
        return 1;
    } else {
        //  Not supported.
        return 0;
    }
#else
    return inet_pton (af_, src_, dst_);
#endif
}

sockaddr_in bind_bsd_socket (int socket)
{
    struct sockaddr_in saddr;
    memset (&saddr, 0, sizeof (saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = INADDR_ANY;
#if !defined(_WIN32_WINNT) || (_WIN32_WINNT >= 0x0600)
    saddr.sin_port = 0;
#else
    saddr.sin_port = htons (PORT_6);
#endif

    TEST_ASSERT_SUCCESS_RAW_ERRNO (
      bind (socket, (struct sockaddr *) &saddr, sizeof (saddr)));

#if !defined(_WIN32_WINNT) || (_WIN32_WINNT >= 0x0600)
    socklen_t saddr_len = sizeof (saddr);
    TEST_ASSERT_SUCCESS_RAW_ERRNO (
      getsockname (socket, (struct sockaddr *) &saddr, &saddr_len));
#endif

    return saddr;
}

bool streq (const char *lhs, const char *rhs)
{
    return strcmp (lhs, rhs) == 0;
}

bool strneq (const char *lhs, const char *rhs)
{
    return strcmp (lhs, rhs) != 0;
}
