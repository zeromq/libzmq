/*
    Copyright (c) 2007-2010 iMatix Corporation

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

#include "signaler.hpp"
#include "platform.hpp"
#include "err.hpp"
#include "fd.hpp"
#include "ip.hpp"

#if defined ZMQ_HAVE_OPENVMS
#include <netinet/tcp.h>
#elif defined ZMQ_HAVE_WINDOWS 
#include "windows.hpp"
#else
#include <unistd.h>
#include <fcntl.h>
#endif

#if defined ZMQ_HAVE_EVENTFD

#include <sys/eventfd.h>

zmq::signaler_t::signaler_t ()
{
    //  Create eventfd object.
    fd = eventfd (0, 0);
    errno_assert (fd != -1);

    //  Set to non-blocking mode.
    int flags = fcntl (fd, F_GETFL, 0);
    if (flags == -1)
        flags = 0;
    int rc = fcntl (fd, F_SETFL, flags | O_NONBLOCK);
    errno_assert (rc != -1);
}

zmq::signaler_t::~signaler_t ()
{
    int rc = close (fd);
    errno_assert (rc != -1);
}

void zmq::signaler_t::signal (int signal_)
{
    zmq_assert (signal_ >= 0 && signal_ < 64);
    uint64_t inc = 1;
    inc <<= signal_;
    ssize_t sz = write (fd, &inc, sizeof (uint64_t));
    errno_assert (sz == sizeof (uint64_t));
}

uint64_t zmq::signaler_t::poll ()
{
    //  Set to blocking mode.
    int flags = fcntl (fd, F_GETFL, 0);
    if (flags == -1)
        flags = 0;
    int rc = fcntl (fd, F_SETFL, flags & ~O_NONBLOCK);
    errno_assert (rc != -1);

    uint64_t signals;
    ssize_t sz;
    while (true) {
        sz = read (fd, &signals, sizeof (uint64_t));
        if (sz == -1) {
            if (errno == EAGAIN || errno == EINTR)
                continue;
            errno_assert (false);
        }
        break;
    }

    //  Set to non-blocking mode.
    rc = fcntl (fd, F_SETFL, flags | O_NONBLOCK);
    errno_assert (rc != -1);

    return signals;
}

uint64_t zmq::signaler_t::check ()
{
    uint64_t signals;
    ssize_t sz = read (fd, &signals, sizeof (uint64_t));
    if (sz == -1 && (errno == EAGAIN || errno == EINTR))
        return 0;
    errno_assert (sz != -1);
    return signals;
}

zmq::fd_t zmq::signaler_t::get_fd ()
{
    return fd;
}

#elif defined ZMQ_HAVE_WINDOWS

zmq::signaler_t::signaler_t ()
{
    //  Windows have no 'socketpair' function. CreatePipe is no good as pipe
    //  handles cannot be polled on. Here we create the socketpair by hand.

    struct sockaddr_in addr;
    SOCKET listener;
    int addrlen = sizeof (addr);
           
    w = INVALID_SOCKET; 
    r = INVALID_SOCKET;
    
    fd_t rcs = (listener = socket (AF_INET, SOCK_STREAM, 0));
    wsa_assert (rcs != INVALID_SOCKET);

    memset (&addr, 0, sizeof (addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
    addr.sin_port = 0;
            
    int rc = bind (listener, (const struct sockaddr*) &addr, sizeof (addr));
    wsa_assert (rc != SOCKET_ERROR);

    rc = getsockname (listener, (struct sockaddr*) &addr, &addrlen);
    wsa_assert (rc != SOCKET_ERROR);
            
    //  Listen for incomming connections.
    rc = listen (listener, 1);
    wsa_assert (rc != SOCKET_ERROR);
                     
    //  Create the socket.
    w = WSASocket (AF_INET, SOCK_STREAM, 0, NULL, 0,  0);
    wsa_assert (w != INVALID_SOCKET);
                      
    //  Connect to the remote peer.
    rc = connect (w, (sockaddr *) &addr, sizeof (addr));
    wsa_assert (rc != SOCKET_ERROR);
                                    
    //  Accept connection from w.
    r = accept (listener, NULL, NULL);
    wsa_assert (r != INVALID_SOCKET);

    //  Set the read site of the pair to non-blocking mode.
    unsigned long argp = 1;
    rc = ioctlsocket (r, FIONBIO, &argp);
    wsa_assert (rc != SOCKET_ERROR);

    //  We don't need the listening socket anymore. Close it.
    rc = closesocket (listener);
    wsa_assert (rc != SOCKET_ERROR);
}

zmq::signaler_t::~signaler_t ()
{
    int rc = closesocket (w);
    wsa_assert (rc != SOCKET_ERROR);

    rc = closesocket (r);
    wsa_assert (rc != SOCKET_ERROR);
}

void zmq::signaler_t::signal (int signal_)
{
    //  TODO: Note that send is a blocking operation.
    //  How should we behave if the signal cannot be written to the signaler?

    zmq_assert (signal_ >= 0 && signal_ < 64);
    char c = (char) signal_;
    int rc = send (w, &c, 1, 0);
    win_assert (rc != SOCKET_ERROR);
}

uint64_t zmq::signaler_t::poll ()
{
    //  Switch to blocking mode.
    unsigned long argp = 0;
    int rc = ioctlsocket (r, FIONBIO, &argp);
    wsa_assert (rc != SOCKET_ERROR);

    //  Get the signals. Given that we are in the blocking mode now,
    //  there should be at least a single signal returned.
    uint64_t signals = check ();
    zmq_assert (signals);

    //  Switch back to non-blocking mode.
    argp = 1;
    rc = ioctlsocket (r, FIONBIO, &argp);
    wsa_assert (rc != SOCKET_ERROR);

    return signals;
}

uint64_t zmq::signaler_t::check ()
{
    unsigned char buffer [32];
    int nbytes = recv (r, (char*) buffer, 32, 0);
    if (nbytes == -1 && WSAGetLastError () == WSAEWOULDBLOCK)
        return 0;
    wsa_assert (nbytes != -1);

    uint64_t signals = 0;
    for (int pos = 0; pos != nbytes; pos++) {
        zmq_assert (buffer [pos] < 64);
        signals |= (uint64_t (1) << (buffer [pos]));
    }
    return signals;
}

zmq::fd_t zmq::signaler_t::get_fd ()
{
    return r;
}

#elif defined ZMQ_HAVE_HPUX || defined ZMQ_HAVE_AIX

#include <sys/types.h>
#include <sys/socket.h>

zmq::signaler_t::signaler_t ()
{
    int sv [2];
    int rc = socketpair (AF_UNIX, SOCK_STREAM, 0, sv);
    errno_assert (rc == 0);
    w = sv [0];
    r = sv [1];

    //  Set the reader to non-blocking mode.
    int flags = fcntl (r, F_GETFL, 0);
    if (flags == -1)
        flags = 0;
    rc = fcntl (r, F_SETFL, flags | O_NONBLOCK);
    errno_assert (rc != -1);
}

zmq::signaler_t::~signaler_t ()
{
    close (w);
    close (r);
}

void zmq::signaler_t::signal (int signal_)
{
    zmq_assert (signal_ >= 0 && signal_ < 64);
    unsigned char c = (unsigned char) signal_;
    ssize_t nbytes = send (w, &c, 1, 0);
    errno_assert (nbytes == 1);
}

uint64_t zmq::signaler_t::poll ()
{
    //  Set the reader to blocking mode.
    int flags = fcntl (r, F_GETFL, 0);
    if (flags == -1)
        flags = 0;
    int rc = fcntl (r, F_SETFL, flags & ~O_NONBLOCK);
    errno_assert (rc != -1);

    //  Poll for events.
    uint64_t signals = check ();

    //  Set the reader to non-blocking mode.
    flags = fcntl (r, F_GETFL, 0);
    if (flags == -1)
        flags = 0;
    rc = fcntl (r, F_SETFL, flags | O_NONBLOCK);
    errno_assert (rc != -1);

    return signals;
}

uint64_t zmq::signaler_t::check ()
{
    unsigned char buffer [64];
    ssize_t nbytes = recv (r, buffer, 64, 0);
    if (nbytes == -1 && errno == EAGAIN)
        return 0;
    zmq_assert (nbytes != -1);

    uint64_t signals = 0;
    for (int pos = 0; pos != nbytes; pos ++) {
        zmq_assert (buffer [pos] < 64);
        signals |= (uint64_t (1) << (buffer [pos]));
    }
    return signals;
}

zmq::fd_t zmq::signaler_t::get_fd ()
{
    return r;
}

#else

#include <sys/types.h>
#include <sys/socket.h>

zmq::signaler_t::signaler_t ()
{
    int sv [2];
    int rc = socketpair (AF_UNIX, SOCK_STREAM, 0, sv);
    errno_assert (rc == 0);
    w = sv [0];
    r = sv [1];
}

zmq::signaler_t::~signaler_t ()
{
    close (w);
    close (r);
}

void zmq::signaler_t::signal (int signal_)
{
    //  TODO: Note that send is a blocking operation.
    //  How should we behave if the signal cannot be written to the signaler?

    zmq_assert (signal_ >= 0 && signal_ < 64);
    unsigned char c = (unsigned char) signal_;
    ssize_t nbytes = send (w, &c, 1, 0);
    errno_assert (nbytes == 1);
}

uint64_t zmq::signaler_t::poll ()
{
    unsigned char buffer [64];
    ssize_t nbytes = recv (r, buffer, 64, 0);
    zmq_assert (nbytes != -1);

    uint64_t signals = 0;
    for (int pos = 0; pos != nbytes; pos ++) {
        zmq_assert (buffer [pos] < 64);
        signals |= (uint64_t (1) << (buffer [pos]));
    }
    return signals;
}

uint64_t zmq::signaler_t::check ()
{
    unsigned char buffer [64];
    ssize_t nbytes = recv (r, buffer, 64, MSG_DONTWAIT);
    if (nbytes == -1 && errno == EAGAIN)
        return 0;
    zmq_assert (nbytes != -1);

    uint64_t signals = 0;
    for (int pos = 0; pos != nbytes; pos ++) {
        zmq_assert (buffer [pos] < 64);
        signals |= (uint64_t (1) << (buffer [pos]));
    }
    return signals;
}

zmq::fd_t zmq::signaler_t::get_fd ()
{
    return r;
}

#endif

#if defined ZMQ_HAVE_OPENVMS

int zmq::signaler_t::socketpair (int domain_, int type_, int protocol_,
    int sv_ [2])
{
    int listener;
    sockaddr_in lcladdr;
    socklen_t lcladdr_len;
    int rc;
    int on = 1;

    zmq_assert (type_ == SOCK_STREAM);

    //  Fill in the localhost address (127.0.0.1).
    memset (&lcladdr, 0, sizeof (lcladdr));
    lcladdr.sin_family = AF_INET;
    lcladdr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
    lcladdr.sin_port = 0;

    listener = socket (AF_INET, SOCK_STREAM, 0);
    errno_assert (listener != -1);

    rc = setsockopt (listener, IPPROTO_TCP, TCP_NODELAY, &on, sizeof (on));
    errno_assert (rc != -1);

    rc = setsockopt (listener, IPPROTO_TCP, TCP_NODELACK, &on, sizeof (on));
    errno_assert (rc != -1);

    rc = bind(listener, (struct sockaddr*) &lcladdr, sizeof (lcladdr));
    errno_assert (rc != -1);
        
    lcladdr_len = sizeof (lcladdr);

    rc = getsockname (listener, (struct sockaddr*) &lcladdr, &lcladdr_len);
    errno_assert (rc != -1);

    rc = listen (listener, 1);
    errno_assert (rc != -1);

    sv_ [0] = socket (AF_INET, SOCK_STREAM, 0);
    errno_assert (rc != -1);

    rc = setsockopt (sv_ [0], IPPROTO_TCP, TCP_NODELAY, &on, sizeof (on));
    errno_assert (rc != -1);

    rc = setsockopt (sv_ [0], IPPROTO_TCP, TCP_NODELACK, &on, sizeof (on));
    errno_assert (rc != -1);

    rc = connect (sv_ [0], (struct sockaddr*) &lcladdr, sizeof (lcladdr));
    errno_assert (rc != -1);

    sv_ [1] = accept (listener, NULL, NULL);
    errno_assert (sv_ [1] != -1);

    close (listener);

    return 0;
}

#endif

