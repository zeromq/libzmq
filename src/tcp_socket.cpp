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

#include "tcp_socket.hpp"
#include "platform.hpp"
#include "err.hpp"

#ifdef ZMQ_HAVE_WINDOWS

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

zmq::tcp_socket_t::tcp_socket_t () :
    s (retired_fd)
{
}

zmq::tcp_socket_t::~tcp_socket_t ()
{
    if (s != retired_fd)
        close ();
}

int zmq::tcp_socket_t::open (fd_t fd_)
{
    assert (s == retired_fd);
    s = fd_;
    return 0;
}

int zmq::tcp_socket_t::close ()
{
    zmq_assert (s != retired_fd);
    int rc = ::close (s);
    if (rc != 0)
        return -1;
    s = retired_fd;
    return 0;
}

zmq::fd_t zmq::tcp_socket_t::get_fd ()
{
    return s;
}

int zmq::tcp_socket_t::write (const void *data, int size)
{
    ssize_t nbytes = send (s, data, size, 0);

    //  Several errors are OK. When speculative write is being done we may not
    //  be able to write a single byte to the socket. Also, SIGSTOP issued
    //  by a debugging tool can result in EINTR error.
    if (nbytes == -1 && (errno == EAGAIN || errno == EWOULDBLOCK ||
          errno == EINTR))
        return 0;

    //  Signalise peer failure.
    if (nbytes == -1 && errno == ECONNRESET)
        return -1;

    errno_assert (nbytes != -1);
    return (size_t) nbytes;
}

int zmq::tcp_socket_t::read (void *data, int size)
{
    ssize_t nbytes = recv (s, data, size, 0);

    //  Several errors are OK. When speculative read is being done we may not
    //  be able to read a single byte to the socket. Also, SIGSTOP issued
    //  by a debugging tool can result in EINTR error.
    if (nbytes == -1 && (errno == EAGAIN || errno == EWOULDBLOCK ||
          errno == EINTR))
        return 0;

    //  Signalise peer failure.
    if (nbytes == -1 && (errno == ECONNRESET || errno == ECONNREFUSED))
        return -1;

    errno_assert (nbytes != -1);

    //  Orderly shutdown by the other peer.
    if (nbytes == 0)
        return -1;

    return (size_t) nbytes;
}

#endif

