/*
    Copyright (c) 2007-2010 iMatix Corporation

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

#include "mailbox.hpp"
#include "platform.hpp"
#include "err.hpp"
#include "fd.hpp"
#include "ip.hpp"

#if defined ZMQ_HAVE_WINDOWS
#include "windows.hpp"
#else
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#endif

zmq::fd_t zmq::mailbox_t::get_fd ()
{
    return r;
}

#if defined ZMQ_HAVE_WINDOWS

zmq::mailbox_t::mailbox_t ()
{
    //  Create the socketpair for signalling.
    int rc = make_socketpair (&r, &w);
    errno_assert (rc == 0);

    //  Set the writer to non-blocking mode.
    unsigned long argp = 1;
    rc = ioctlsocket (w, FIONBIO, &argp);
    wsa_assert (rc != SOCKET_ERROR);

    //  Set the reader to non-blocking mode.
    argp = 1;
    rc = ioctlsocket (r, FIONBIO, &argp);
    wsa_assert (rc != SOCKET_ERROR);
}

zmq::mailbox_t::~mailbox_t ()
{
    int rc = closesocket (w);
    wsa_assert (rc != SOCKET_ERROR);

    rc = closesocket (r);
    wsa_assert (rc != SOCKET_ERROR);
}

void zmq::mailbox_t::send (const command_t &cmd_)
{
    //  TODO: Implement SNDBUF auto-resizing as for POSIX platforms.
    //  In the mean time, the following code with assert if the send()
    //  call would block.
    int nbytes = ::send (w, (char *)&cmd_, sizeof (command_t), 0);
    wsa_assert (nbytes != SOCKET_ERROR);
    zmq_assert (nbytes == sizeof (command_t));
}

int zmq::mailbox_t::recv (command_t *cmd_, bool block_)
{
    //  If required, set the reader to blocking mode.
    if (block_) {
        unsigned long argp = 0;
        int rc = ioctlsocket (r, FIONBIO, &argp);
        wsa_assert (rc != SOCKET_ERROR);
    }

    //  Attempt to read an entire command. Returns EAGAIN if non-blocking
    //  and a command is not available. Save value of errno if we wish to pass
    //  it to caller.
    int err = 0;
    int nbytes = ::recv (r, (char *)cmd_, sizeof (command_t), 0);
    if (nbytes == -1 && WSAGetLastError () == WSAEWOULDBLOCK)
        err = EAGAIN;

    //  Re-set the reader to non-blocking mode.
    if (block_) {
        unsigned long argp = 1;
        int rc = ioctlsocket (r, FIONBIO, &argp);
        wsa_assert (rc != SOCKET_ERROR);
    }

    //  If the recv failed, return with the saved errno.
    if (err != 0) {
        errno = err;
        return -1;
    }

    //  Sanity check for success.
    wsa_assert (nbytes != SOCKET_ERROR);

    //  Check whether we haven't got half of command.
    zmq_assert (nbytes == sizeof (command_t));

    return 0;
}

#else

zmq::mailbox_t::mailbox_t ()
{
#ifdef PIPE_BUF
    //  Make sure that command can be written to the socket in atomic fashion.
    //  If this wasn't guaranteed, commands from different threads would be
    //  interleaved.
    zmq_assert (sizeof (command_t) <= PIPE_BUF);
#endif

    //  Create the socketpair for signaling.
    int rc = make_socketpair (&r, &w);
    errno_assert (rc == 0);

    //  Set the writer to non-blocking mode.
    int flags = fcntl (w, F_GETFL, 0);
    errno_assert (flags >= 0);
    rc = fcntl (w, F_SETFL, flags | O_NONBLOCK);
    errno_assert (rc == 0);

#ifndef MSG_DONTWAIT
    //  Set the reader to non-blocking mode.
    flags = fcntl (r, F_GETFL, 0);
    errno_assert (flags >= 0);
    rc = fcntl (r, F_SETFL, flags | O_NONBLOCK);
    errno_assert (rc == 0);
#endif
}

zmq::mailbox_t::~mailbox_t ()
{
    close (w);
    close (r);
}

void zmq::mailbox_t::send (const command_t &cmd_)
{
    //  Attempt to write an entire command without blocking.
    ssize_t nbytes;
    do {
        nbytes = ::send (w, &cmd_, sizeof (command_t), 0);
    } while (nbytes == -1 && errno == EINTR);

    //  Attempt to increase mailbox SNDBUF if the send failed.
    if (nbytes == -1 && errno == EAGAIN) {
        int old_sndbuf, new_sndbuf;
        socklen_t sndbuf_size = sizeof old_sndbuf;

        //  Retrieve current send buffer size.
        int rc = getsockopt (w, SOL_SOCKET, SO_SNDBUF, &old_sndbuf,
            &sndbuf_size);
        errno_assert (rc == 0);
        new_sndbuf = old_sndbuf * 2;

        //  Double the new send buffer size.
        rc = setsockopt (w, SOL_SOCKET, SO_SNDBUF, &new_sndbuf, sndbuf_size);
        errno_assert (rc == 0);

        //  Verify that the OS actually honored the request.
        rc = getsockopt (w, SOL_SOCKET, SO_SNDBUF, &new_sndbuf, &sndbuf_size);
        errno_assert (rc == 0);
        zmq_assert (new_sndbuf > old_sndbuf);

        //  Retry the sending operation; at this point it must succeed.
        do {
            nbytes = ::send (w, &cmd_, sizeof (command_t), 0);
        } while (nbytes == -1 && errno == EINTR);
    }
    errno_assert (nbytes != -1);

    //  This should never happen as we've already checked that command size is
    //  less than PIPE_BUF.
    zmq_assert (nbytes == sizeof (command_t));
}

int zmq::mailbox_t::recv (command_t *cmd_, bool block_)
{
#ifdef MSG_DONTWAIT

    //  Attempt to read an entire command. Returns EAGAIN if non-blocking
    //  mode is requested and a command is not available.
    ssize_t nbytes = ::recv (r, cmd_, sizeof (command_t),
        block_ ? 0 : MSG_DONTWAIT);
    if (nbytes == -1 && (errno == EAGAIN || errno == EINTR))
        return -1;
#else

    //  If required, set the reader to blocking mode.
    if (block_) {
        int flags = fcntl (r, F_GETFL, 0);
        errno_assert (flags >= 0);
        int rc = fcntl (r, F_SETFL, flags & ~O_NONBLOCK);
        errno_assert (rc == 0);
    }

    //  Attempt to read an entire command. Returns EAGAIN if non-blocking
    //  and a command is not available. Save value of errno if we wish to pass
    //  it to caller.
    int err = 0;
    ssize_t nbytes = ::recv (r, cmd_, sizeof (command_t), 0);
    if (nbytes == -1 && (errno == EAGAIN || errno == EINTR))  
        err = errno;

    //  Re-set the reader to non-blocking mode.
    if (block_) {
        int flags = fcntl (r, F_GETFL, 0);
        errno_assert (flags >= 0);
        int rc = fcntl (r, F_SETFL, flags | O_NONBLOCK);
        errno_assert (rc == 0);
    }

    //  If the recv failed, return with the saved errno if set.
    if (err != 0) {
        errno = err;
        return -1;
    }

#endif

    //  Sanity check for success.
    errno_assert (nbytes != -1);

    //  Check whether we haven't got half of command.
    zmq_assert (nbytes == sizeof (command_t));

    return 0;
}

#endif

int zmq::mailbox_t::make_socketpair (fd_t *r_, fd_t *w_)
{
#if defined ZMQ_HAVE_WINDOWS

    //  Windows has no 'socketpair' function. CreatePipe is no good as pipe
    //  handles cannot be polled on. Here we create the socketpair by hand.
    *w_ = INVALID_SOCKET;
    *r_ = INVALID_SOCKET;

    //  Create listening socket.
    SOCKET listener;
    listener = socket (AF_INET, SOCK_STREAM, 0);
    wsa_assert (listener != INVALID_SOCKET);

    //  Set SO_REUSEADDR and TCP_NODELAY on listening socket.
    BOOL so_reuseaddr = 1;
    int rc = setsockopt (listener, SOL_SOCKET, SO_REUSEADDR,
        (char *)&so_reuseaddr, sizeof (so_reuseaddr));
    wsa_assert (rc != SOCKET_ERROR);
    BOOL tcp_nodelay = 1;
    rc = setsockopt (listener, IPPROTO_TCP, TCP_NODELAY,
        (char *)&tcp_nodelay, sizeof (tcp_nodelay));
    wsa_assert (rc != SOCKET_ERROR);

    //  Bind listening socket to any free local port.
    struct sockaddr_in addr;
    memset (&addr, 0, sizeof (addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
    addr.sin_port = 0;
    rc = bind (listener, (const struct sockaddr*) &addr, sizeof (addr));
    wsa_assert (rc != SOCKET_ERROR);

    //  Retrieve local port listener is bound to (into addr).
    int addrlen = sizeof (addr);
    rc = getsockname (listener, (struct sockaddr*) &addr, &addrlen);
    wsa_assert (rc != SOCKET_ERROR);

    //  Listen for incomming connections.
    rc = listen (listener, 1);
    wsa_assert (rc != SOCKET_ERROR);

    //  Create the writer socket.
    *w_ = WSASocket (AF_INET, SOCK_STREAM, 0, NULL, 0,  0);
    wsa_assert (*w_ != INVALID_SOCKET);

    //  Set TCP_NODELAY on writer socket.
    rc = setsockopt (*w_, IPPROTO_TCP, TCP_NODELAY,
        (char *)&tcp_nodelay, sizeof (tcp_nodelay));
    wsa_assert (rc != SOCKET_ERROR);

    //  Connect writer to the listener.
    rc = connect (*w_, (sockaddr *) &addr, sizeof (addr));
    wsa_assert (rc != SOCKET_ERROR);

    //  Accept connection from writer.
    *r_ = accept (listener, NULL, NULL);
    wsa_assert (*r_ != INVALID_SOCKET);

    //  We don't need the listening socket anymore. Close it.
    rc = closesocket (listener);
    wsa_assert (rc != SOCKET_ERROR);

    return 0;

#elif defined ZMQ_HAVE_OPENVMS

    //  Whilst OpenVMS supports socketpair - it maps to AF_INET only.  Further,
    //  it does not set the socket options TCP_NODELAY and TCP_NODELACK which
    //  can lead to performance problems.
    //
    //  The bug will be fixed in V5.6 ECO4 and beyond.  In the meantime, we'll
    //  create the socket pair manually.
    sockaddr_in lcladdr;
    memset (&lcladdr, 0, sizeof (lcladdr));
    lcladdr.sin_family = AF_INET;
    lcladdr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
    lcladdr.sin_port = 0;

    int listener = socket (AF_INET, SOCK_STREAM, 0);
    errno_assert (listener != -1);

    int on = 1;
    int rc = setsockopt (listener, IPPROTO_TCP, TCP_NODELAY, &on, sizeof (on));
    errno_assert (rc != -1);

    rc = setsockopt (listener, IPPROTO_TCP, TCP_NODELACK, &on, sizeof (on));
    errno_assert (rc != -1);

    rc = bind(listener, (struct sockaddr*) &lcladdr, sizeof (lcladdr));
    errno_assert (rc != -1);

    socklen_t lcladdr_len = sizeof (lcladdr);

    rc = getsockname (listener, (struct sockaddr*) &lcladdr, &lcladdr_len);
    errno_assert (rc != -1);

    rc = listen (listener, 1);
    errno_assert (rc != -1);

    *w_ = socket (AF_INET, SOCK_STREAM, 0);
    errno_assert (*w_ != -1);

    rc = setsockopt (*w_, IPPROTO_TCP, TCP_NODELAY, &on, sizeof (on));
    errno_assert (rc != -1);

    rc = setsockopt (*w_, IPPROTO_TCP, TCP_NODELACK, &on, sizeof (on));
    errno_assert (rc != -1);

    rc = connect (*w_, (struct sockaddr*) &lcladdr, sizeof (lcladdr));
    errno_assert (rc != -1);

    *r_ = accept (listener, NULL, NULL);
    errno_assert (*r_ != -1);

    close (listener);

    return 0;

#else // All other implementations support socketpair()

    int sv [2];
    int rc = socketpair (AF_UNIX, SOCK_STREAM, 0, sv);
    errno_assert (rc == 0);
    *w_ = sv [0];
    *r_ = sv [1];
    return 0;

#endif
}

