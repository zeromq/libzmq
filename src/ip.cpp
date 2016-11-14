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

#include "precompiled.hpp"
#include "ip.hpp"
#include "err.hpp"

#if !defined ZMQ_HAVE_WINDOWS
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#endif

#if defined ZMQ_HAVE_OPENVMS
#include <ioctl.h>
#endif

zmq::fd_t zmq::open_socket (int domain_, int type_, int protocol_)
{
    //  Setting this option result in sane behaviour when exec() functions
    //  are used. Old sockets are closed and don't block TCP ports etc.
#if defined ZMQ_HAVE_SOCK_CLOEXEC
    type_ |= SOCK_CLOEXEC;
#endif

    fd_t s = socket (domain_, type_, protocol_);
#ifdef ZMQ_HAVE_WINDOWS
    if (s == INVALID_SOCKET)
        return INVALID_SOCKET;
#else
    if (s == -1)
        return -1;
#endif

    //  If there's no SOCK_CLOEXEC, let's try the second best option. Note that
    //  race condition can cause socket not to be closed (if fork happens
    //  between socket creation and this point).
#if !defined ZMQ_HAVE_SOCK_CLOEXEC && defined FD_CLOEXEC
    int rc = fcntl (s, F_SETFD, FD_CLOEXEC);
    errno_assert (rc != -1);
#endif

    //  On Windows, preventing sockets to be inherited by child processes.
#if defined ZMQ_HAVE_WINDOWS && defined HANDLE_FLAG_INHERIT
    BOOL brc = SetHandleInformation ((HANDLE) s, HANDLE_FLAG_INHERIT, 0);
    win_assert (brc);
#endif

    return s;
}

void zmq::unblock_socket (fd_t s_)
{
#if defined ZMQ_HAVE_WINDOWS
    u_long nonblock = 1;
    int rc = ioctlsocket (s_, FIONBIO, &nonblock);
    wsa_assert (rc != SOCKET_ERROR);
#elif defined ZMQ_HAVE_OPENVMS
    int nonblock = 1;
    int rc = ioctl (s_, FIONBIO, &nonblock);
    errno_assert (rc != -1);
#else
    int flags = fcntl (s_, F_GETFL, 0);
    if (flags == -1)
        flags = 0;
    int rc = fcntl (s_, F_SETFL, flags | O_NONBLOCK);
    errno_assert (rc != -1);
#endif
}

void zmq::enable_ipv4_mapping (fd_t s_)
{
  (void) s_;

#ifdef IPV6_V6ONLY
#ifdef ZMQ_HAVE_WINDOWS
    DWORD flag = 0;
#else
    int flag = 0;
#endif
    int rc = setsockopt (s_, IPPROTO_IPV6, IPV6_V6ONLY, (const char*) &flag,
        sizeof (flag));
#ifdef ZMQ_HAVE_WINDOWS
    wsa_assert (rc != SOCKET_ERROR);
#else
    errno_assert (rc == 0);
#endif
#endif
}

int zmq::get_peer_ip_address (fd_t sockfd_, std::string &ip_addr_)
{
    int rc;
    struct sockaddr_storage ss;

#if defined ZMQ_HAVE_HPUX || defined ZMQ_HAVE_WINDOWS
    int addrlen = static_cast <int> (sizeof ss);
#else
    socklen_t addrlen = sizeof ss;
#endif
    rc = getpeername (sockfd_, (struct sockaddr*) &ss, &addrlen);
#ifdef ZMQ_HAVE_WINDOWS
    if (rc == SOCKET_ERROR) {
        const int last_error = WSAGetLastError();
        wsa_assert (last_error != WSANOTINITIALISED &&
                    last_error != WSAEFAULT &&
                    last_error != WSAEINPROGRESS &&
                    last_error != WSAENOTSOCK);
        return 0;
    }
#else
    if (rc == -1) {
        errno_assert (errno != EBADF &&
                      errno != EFAULT &&
                      errno != ENOTSOCK);
        return 0;
    }
#endif

    char host [NI_MAXHOST];
    rc = getnameinfo ((struct sockaddr*) &ss, addrlen, host, sizeof host,
        NULL, 0, NI_NUMERICHOST);
    if (rc != 0)
        return 0;

    ip_addr_ = host;

    union {
        struct sockaddr sa;
        struct sockaddr_storage sa_stor;
    } u;

    u.sa_stor = ss;
    return (int) u.sa.sa_family;
}

void zmq::set_ip_type_of_service (fd_t s_, int iptos)
{
    int rc = setsockopt(s_, IPPROTO_IP, IP_TOS, reinterpret_cast<const char*>(&iptos), sizeof(iptos));

#ifdef ZMQ_HAVE_WINDOWS
    wsa_assert (rc != SOCKET_ERROR);
#else
    errno_assert (rc == 0);
#endif

    rc = setsockopt(
        s_,
        IPPROTO_IPV6,
        IPV6_TCLASS,
        reinterpret_cast<const char*>(&iptos),
        sizeof(iptos));

    //  If IPv6 is not enabled ENOPROTOOPT will be returned on Windows and
    //  Linux, and EINVAL on OSX
#ifdef ZMQ_HAVE_WINDOWS
    if (rc == SOCKET_ERROR) {
        const int last_error = WSAGetLastError();
        wsa_assert (last_error == WSAENOPROTOOPT);
    }
#else
    if (rc == -1) {
        errno_assert (errno == ENOPROTOOPT ||
                      errno == EINVAL);
    }
#endif
}
