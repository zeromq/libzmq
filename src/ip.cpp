/*
    Copyright (c) 2007-2013 Contributors as noted in the AUTHORS file

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "ip.hpp"
#include "err.hpp"
#include "platform.hpp"

#if defined ZMQ_HAVE_WINDOWS
#include "windows.hpp"
#else
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

bool zmq::get_peer_ip_address (fd_t sockfd_, std::string &ip_addr_)
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
        wsa_assert (WSAGetLastError () != WSANOTINITIALISED &&
                    WSAGetLastError () != WSAEFAULT &&
                    WSAGetLastError () != WSAEINPROGRESS &&
                    WSAGetLastError () != WSAENOTSOCK);
        return false;
    }
#else
    if (rc == -1) {
        errno_assert (errno != EBADF &&
                      errno != EFAULT &&
                      errno != EINVAL &&
                      errno != ENOTSOCK);
        return false;
    }
#endif

    char host [NI_MAXHOST];
    rc = getnameinfo ((struct sockaddr*) &ss, addrlen, host, sizeof host,
        NULL, 0, NI_NUMERICHOST);
    if (rc != 0)
        return false;

    ip_addr_ = host;
    return true;
}
