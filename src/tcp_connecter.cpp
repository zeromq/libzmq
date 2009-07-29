/*
    Copyright (c) 2007-2009 FastMQ Inc.

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the Lesser GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    Lesser GNU General Public License for more details.

    You should have received a copy of the Lesser GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "tcp_connecter.hpp"
#include "platform.hpp"
#include "ip.hpp"
#include "err.hpp"

#ifdef ZS_HAVE_WINDOWS

#include "windows.hpp"
#error

#else

#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>

zs::tcp_connecter_t::tcp_connecter_t () :
    s (retired_fd)
{
}

zs::tcp_connecter_t::~tcp_connecter_t ()
{
    if (s != retired_fd)
        close ();
}

int zs::tcp_connecter_t::open (const char *addr_)
{
    zs_assert (s == retired_fd);

    //  Convert the hostname into sockaddr_in structure.
    sockaddr_in address;
    int rc = resolve_ip_hostname (&address, addr_);
    if (rc != 0)
        return -1;

    //  Create the socket.
    s = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == -1)
        return -1;

    // Set to non-blocking mode.
    int flags = fcntl (s, F_GETFL, 0);
    if (flags == -1) 
        flags = 0;
    rc = fcntl (s, F_SETFL, flags | O_NONBLOCK);
    errno_assert (rc != -1);

    //  Disable Nagle's algorithm.
    int flag = 1;
    rc = setsockopt (s, IPPROTO_TCP, TCP_NODELAY, (char*) &flag, sizeof (int));
    errno_assert (rc == 0);

#ifdef ZS_HAVE_OPENVMS
    //  Disable delayed acknowledgements.
    flag = 1;
    rc = setsockopt (s, IPPROTO_TCP, TCP_NODELACK, (char*) &flag, sizeof (int));
    errno_assert (rc != SOCKET_ERROR);
#endif

    //  Connect to the remote peer.
    rc = ::connect (s, (sockaddr*) &address, sizeof address);

    //  Connect was successfull immediately.
    if (rc == 0)
        return 0;

    //  Asynchronous connect was launched.
    if (rc == -1 && errno == EINPROGRESS)
        return 1;

    //  Error occured.
    int err = errno;
    close ();
    errno = err;
    return -1;
}

int zs::tcp_connecter_t::close ()
{
    zs_assert (s != retired_fd);
    int rc = ::close (s);
    if (rc != 0)
        return -1;
    s = retired_fd;
    return 0;
}

zs::fd_t zs::tcp_connecter_t::get_fd ()
{
    return s;
}

zs::fd_t zs::tcp_connecter_t::connect ()
{
    //  Following code should handle both Berkeley-derived socket
    //  implementations and Solaris.
    int err = 0;
    socklen_t len = sizeof err;
    int rc = getsockopt (s, SOL_SOCKET, SO_ERROR, (char*) &err, &len);
    if (rc == -1)
        err = errno;
    if (err != 0) {
        close ();
        errno = err;
        return retired_fd;
    }

    fd_t result = s;
    s = retired_fd;
    return result;
}

#endif
