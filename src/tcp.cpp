/*
    Copyright (c) 2007-2015 Contributors as noted in the AUTHORS file

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

#include "ip.hpp"
#include "tcp.hpp"
#include "err.hpp"
#include "platform.hpp"

#if defined ZMQ_HAVE_WINDOWS
#include "windows.hpp"
#else
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#endif

#if defined ZMQ_HAVE_OPENVMS
#include <ioctl.h>
#endif

void zmq::tune_tcp_socket (fd_t s_)
{
    //  Disable Nagle's algorithm. We are doing data batching on 0MQ level,
    //  so using Nagle wouldn't improve throughput in anyway, but it would
    //  hurt latency.
    int nodelay = 1;
    int rc = setsockopt (s_, IPPROTO_TCP, TCP_NODELAY, (char*) &nodelay,
        sizeof (int));
#ifdef ZMQ_HAVE_WINDOWS
    wsa_assert (rc != SOCKET_ERROR);
#else
    errno_assert (rc == 0);
#endif

#ifdef ZMQ_HAVE_OPENVMS
    //  Disable delayed acknowledgements as they hurt latency is serious manner.
    int nodelack = 1;
    rc = setsockopt (s_, IPPROTO_TCP, TCP_NODELACK, (char*) &nodelack,
        sizeof (int));
    errno_assert (rc != SOCKET_ERROR);
#endif
}

void zmq::set_tcp_send_buffer (fd_t sockfd_, int bufsize_)
{
    const int rc = setsockopt (sockfd_, SOL_SOCKET, SO_SNDBUF,
        (char*) &bufsize_, sizeof bufsize_);
#ifdef ZMQ_HAVE_WINDOWS
    wsa_assert (rc != SOCKET_ERROR);
#else
    errno_assert (rc == 0);
#endif
}

void zmq::set_tcp_receive_buffer (fd_t sockfd_, int bufsize_)
{
    const int rc = setsockopt (sockfd_, SOL_SOCKET, SO_RCVBUF,
        (char*) &bufsize_, sizeof bufsize_);
#ifdef ZMQ_HAVE_WINDOWS
    wsa_assert (rc != SOCKET_ERROR);
#else
    errno_assert (rc == 0);
#endif
}

void zmq::tune_tcp_keepalives (fd_t s_, int keepalive_, int keepalive_cnt_, int keepalive_idle_, int keepalive_intvl_)
{
    // These options are used only under certain #ifdefs below.
    (void)keepalive_;
    (void)keepalive_cnt_;
    (void)keepalive_idle_;
    (void)keepalive_intvl_;

    // If none of the #ifdefs apply, then s_ is unused.
    (void)s_;

    //  Tuning TCP keep-alives if platform allows it
    //  All values = -1 means skip and leave it for OS
#ifdef ZMQ_HAVE_WINDOWS
    if (keepalive_ != -1) {
        tcp_keepalive keepalive_opts;
        keepalive_opts.onoff = keepalive_;
        keepalive_opts.keepalivetime = keepalive_idle_ != -1 ? keepalive_idle_ * 1000 : 7200000;
        keepalive_opts.keepaliveinterval = keepalive_intvl_ != -1 ? keepalive_intvl_ * 1000 : 1000;
        DWORD num_bytes_returned;
        int rc = WSAIoctl(s_, SIO_KEEPALIVE_VALS, &keepalive_opts, sizeof(keepalive_opts), NULL, 0, &num_bytes_returned, NULL, NULL);
        wsa_assert (rc != SOCKET_ERROR);
    }
#else
#ifdef ZMQ_HAVE_SO_KEEPALIVE
    if (keepalive_ != -1) {
        int rc = setsockopt (s_, SOL_SOCKET, SO_KEEPALIVE, (char*) &keepalive_, sizeof (int));
        errno_assert (rc == 0);

#ifdef ZMQ_HAVE_TCP_KEEPCNT
        if (keepalive_cnt_ != -1) {
            int rc = setsockopt (s_, IPPROTO_TCP, TCP_KEEPCNT, &keepalive_cnt_, sizeof (int));
            errno_assert (rc == 0);
        }
#endif // ZMQ_HAVE_TCP_KEEPCNT

#ifdef ZMQ_HAVE_TCP_KEEPIDLE
        if (keepalive_idle_ != -1) {
            int rc = setsockopt (s_, IPPROTO_TCP, TCP_KEEPIDLE, &keepalive_idle_, sizeof (int));
            errno_assert (rc == 0);
        }
#else // ZMQ_HAVE_TCP_KEEPIDLE
#ifdef ZMQ_HAVE_TCP_KEEPALIVE
        if (keepalive_idle_ != -1) {
            int rc = setsockopt (s_, IPPROTO_TCP, TCP_KEEPALIVE, &keepalive_idle_, sizeof (int));
            errno_assert (rc == 0);
        }
#endif // ZMQ_HAVE_TCP_KEEPALIVE
#endif // ZMQ_HAVE_TCP_KEEPIDLE

#ifdef ZMQ_HAVE_TCP_KEEPINTVL
        if (keepalive_intvl_ != -1) {
            int rc = setsockopt (s_, IPPROTO_TCP, TCP_KEEPINTVL, &keepalive_intvl_, sizeof (int));
            errno_assert (rc == 0);
        }
#endif // ZMQ_HAVE_TCP_KEEPINTVL
    }
#endif // ZMQ_HAVE_SO_KEEPALIVE
#endif // ZMQ_HAVE_WINDOWS
}

int zmq::tcp_write (fd_t s_, const void *data_, size_t size_)
{
#ifdef ZMQ_HAVE_WINDOWS

    int nbytes = send (s_, (char*) data_, (int) size_, 0);

    //  If not a single byte can be written to the socket in non-blocking mode
    //  we'll get an error (this may happen during the speculative write).
    if (nbytes == SOCKET_ERROR && WSAGetLastError () == WSAEWOULDBLOCK)
        return 0;

    //  Signalise peer failure.
    if (nbytes == SOCKET_ERROR && (
          WSAGetLastError () == WSAENETDOWN ||
          WSAGetLastError () == WSAENETRESET ||
          WSAGetLastError () == WSAEHOSTUNREACH ||
          WSAGetLastError () == WSAECONNABORTED ||
          WSAGetLastError () == WSAETIMEDOUT ||
          WSAGetLastError () == WSAECONNRESET))
        return -1;

    wsa_assert (nbytes != SOCKET_ERROR);
    return nbytes;

#else
    ssize_t nbytes = send (s_, data_, size_, 0);

    //  Several errors are OK. When speculative write is being done we may not
    //  be able to write a single byte from the socket. Also, SIGSTOP issued
    //  by a debugging tool can result in EINTR error.
    if (nbytes == -1 && (errno == EAGAIN || errno == EWOULDBLOCK ||
          errno == EINTR))
        return 0;

    //  Signalise peer failure.
    if (nbytes == -1) {
        errno_assert (errno != EACCES
                   && errno != EBADF
                   && errno != EDESTADDRREQ
                   && errno != EFAULT
                   && errno != EINVAL
                   && errno != EISCONN
                   && errno != EMSGSIZE
                   && errno != ENOMEM
                   && errno != ENOTSOCK
                   && errno != EOPNOTSUPP);
        return -1;
    }

    return static_cast <int> (nbytes);

#endif
}

int zmq::tcp_read (fd_t s_, void *data_, size_t size_)
{
#ifdef ZMQ_HAVE_WINDOWS

    const int rc = recv (s_, (char*) data_, (int) size_, 0);

    //  If not a single byte can be read from the socket in non-blocking mode
    //  we'll get an error (this may happen during the speculative read).
    if (rc == SOCKET_ERROR) {
        if (WSAGetLastError () == WSAEWOULDBLOCK)
            errno = EAGAIN;
        else {
            wsa_assert (WSAGetLastError () == WSAENETDOWN
                     || WSAGetLastError () == WSAENETRESET
                     || WSAGetLastError () == WSAECONNABORTED
                     || WSAGetLastError () == WSAETIMEDOUT
                     || WSAGetLastError () == WSAECONNRESET
                     || WSAGetLastError () == WSAECONNREFUSED
                     || WSAGetLastError () == WSAENOTCONN);
            errno = wsa_error_to_errno (WSAGetLastError ());
        }
    }

    return rc == SOCKET_ERROR? -1: rc;

#else

    const ssize_t rc = recv (s_, data_, size_, 0);

    //  Several errors are OK. When speculative read is being done we may not
    //  be able to read a single byte from the socket. Also, SIGSTOP issued
    //  by a debugging tool can result in EINTR error.
    if (rc == -1) {
        errno_assert (errno != EBADF
                   && errno != EFAULT
                   && errno != EINVAL
                   && errno != ENOMEM
                   && errno != ENOTSOCK);
        if (errno == EWOULDBLOCK || errno == EINTR)
            errno = EAGAIN;
    }

    return static_cast <int> (rc);

#endif
}
