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

const char *SEQ_END = (const char *) 1;

void bounce (void *server_, void *client_)
{
    const char content[] = "12345678ABCDEFGH12345678abcdefgh";

    //  Send message from client to server
    int rc = zmq_send (client_, content, 32, ZMQ_SNDMORE);
    assert (rc == 32);
    rc = zmq_send (client_, content, 32, 0);
    assert (rc == 32);

    //  Receive message at server side
    char buffer[32];
    rc = zmq_recv (server_, buffer, 32, 0);
    assert (rc == 32);
    //  Check that message is still the same
    assert (memcmp (buffer, content, 32) == 0);
    int rcvmore;
    size_t sz = sizeof (rcvmore);
    rc = zmq_getsockopt (server_, ZMQ_RCVMORE, &rcvmore, &sz);
    assert (rc == 0);
    assert (rcvmore);
    rc = zmq_recv (server_, buffer, 32, 0);
    assert (rc == 32);
    //  Check that message is still the same
    assert (memcmp (buffer, content, 32) == 0);
    rc = zmq_getsockopt (server_, ZMQ_RCVMORE, &rcvmore, &sz);
    assert (rc == 0);
    assert (!rcvmore);

    //  Send two parts back to client
    rc = zmq_send (server_, buffer, 32, ZMQ_SNDMORE);
    assert (rc == 32);
    rc = zmq_send (server_, buffer, 32, 0);
    assert (rc == 32);

    //  Receive the two parts at the client side
    rc = zmq_recv (client_, buffer, 32, 0);
    assert (rc == 32);
    //  Check that message is still the same
    assert (memcmp (buffer, content, 32) == 0);
    rc = zmq_getsockopt (client_, ZMQ_RCVMORE, &rcvmore, &sz);
    assert (rc == 0);
    assert (rcvmore);
    rc = zmq_recv (client_, buffer, 32, 0);
    assert (rc == 32);
    //  Check that message is still the same
    assert (memcmp (buffer, content, 32) == 0);
    rc = zmq_getsockopt (client_, ZMQ_RCVMORE, &rcvmore, &sz);
    assert (rc == 0);
    assert (!rcvmore);
}

void expect_bounce_fail (void *server_, void *client_)
{
    const char *content = "12345678ABCDEFGH12345678abcdefgh";
    char buffer[32];
    int timeout = 250;

    //  Send message from client to server
    int rc = zmq_setsockopt (client_, ZMQ_SNDTIMEO, &timeout, sizeof (int));
    assert (rc == 0);
    rc = zmq_send (client_, content, 32, ZMQ_SNDMORE);
    assert ((rc == 32) || ((rc == -1) && (errno == EAGAIN)));
    rc = zmq_send (client_, content, 32, 0);
    assert ((rc == 32) || ((rc == -1) && (errno == EAGAIN)));

    //  Receive message at server side (should not succeed)
    rc = zmq_setsockopt (server_, ZMQ_RCVTIMEO, &timeout, sizeof (int));
    assert (rc == 0);
    rc = zmq_recv (server_, buffer, 32, 0);
    assert (rc == -1);
    assert (zmq_errno () == EAGAIN);

    //  Send message from server to client to test other direction
    //  If connection failed, send may block, without a timeout
    rc = zmq_setsockopt (server_, ZMQ_SNDTIMEO, &timeout, sizeof (int));
    assert (rc == 0);
    rc = zmq_send (server_, content, 32, ZMQ_SNDMORE);
    assert (rc == 32 || (rc == -1 && zmq_errno () == EAGAIN));
    rc = zmq_send (server_, content, 32, 0);
    assert (rc == 32 || (rc == -1 && zmq_errno () == EAGAIN));

    //  Receive message at client side (should not succeed)
    rc = zmq_setsockopt (client_, ZMQ_RCVTIMEO, &timeout, sizeof (int));
    assert (rc == 0);
    rc = zmq_recv (client_, buffer, 32, 0);
    assert (rc == -1);
    assert (zmq_errno () == EAGAIN);
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

int s_send (void *socket_, const char *string_)
{
    int size = zmq_send (socket_, string_, strlen (string_), 0);
    return size;
}

int s_sendmore (void *socket_, const char *string_)
{
    int size = zmq_send (socket_, string_, strlen (string_), ZMQ_SNDMORE);
    return size;
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
            int rc = zmq_send (socket_, 0, 0, end ? 0 : ZMQ_SNDMORE);
            assert (rc != -1);
        } else {
            int rc = zmq_send (socket_, prev, strlen (prev) + 1,
                               end ? 0 : ZMQ_SNDMORE);
            assert (rc != -1);
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
        int rc = zmq_msg_recv (&msg, socket_, 0);
        assert (rc != -1);

        if (!data)
            assert (zmq_msg_size (&msg) == 0);
        else
            assert (strcmp (data, (const char *) zmq_msg_data (&msg)) == 0);

        data = va_arg (ap, const char *);
        bool end = data == SEQ_END;

        rc = zmq_getsockopt (socket_, ZMQ_RCVMORE, &more, &more_size);
        assert (rc == 0);

        assert (!more == end);
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
    assert (rc == 0 || errno == ETERM);
    rc = zmq_close (socket_);
    assert (rc == 0);
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
    assert (ctx);
    void *rep = zmq_socket (ctx, ZMQ_REP);
    assert (rep);
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

    int rc = bind (socket, (struct sockaddr *) &saddr, sizeof (saddr));
    assert (rc == 0);

#if !defined(_WIN32_WINNT) || (_WIN32_WINNT >= 0x0600)
    socklen_t saddr_len = sizeof (saddr);
    rc = getsockname (socket, (struct sockaddr *) &saddr, &saddr_len);
    assert (rc == 0);
#endif

    return saddr;
}
