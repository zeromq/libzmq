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

//  On AIX, poll.h has to be included before zmq.h to get consistent
//  definition of pollfd structure (AIX uses 'reqevents' and 'retnevents'
//  instead of 'events' and 'revents' and defines macros to map from POSIX-y
//  names to AIX-specific names).
//  zmq.h must be included *after* poll.h for AIX to build properly.
//  precompiled.hpp includes include/zmq.h
#if defined ZMQ_POLL_BASED_ON_POLL && defined ZMQ_HAVE_AIX
#include <poll.h>
#endif

#include "precompiled.hpp"
#include "poller.hpp"

#if defined ZMQ_POLL_BASED_ON_POLL
#if !defined ZMQ_HAVE_WINDOWS && !defined ZMQ_HAVE_AIX
#include <poll.h>
#endif
#elif defined ZMQ_POLL_BASED_ON_SELECT
#if defined ZMQ_HAVE_WINDOWS
#elif defined ZMQ_HAVE_HPUX
#include <sys/param.h>
#include <sys/types.h>
#include <sys/time.h>
#elif defined ZMQ_HAVE_OPENVMS
#include <sys/types.h>
#include <sys/time.h>
#else
#include <sys/select.h>
#endif
#endif

#include "signaler.hpp"
#include "likely.hpp"
#include "stdint.hpp"
#include "config.hpp"
#include "err.hpp"
#include "fd.hpp"
#include "ip.hpp"

#if defined ZMQ_HAVE_EVENTFD
#include <sys/eventfd.h>
#endif

#if !defined ZMQ_HAVE_WINDOWS
#include <unistd.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/socket.h>
#endif

#if !defined (ZMQ_HAVE_WINDOWS)
// Helper to sleep for specific number of milliseconds (or until signal)
//
static int sleep_ms (unsigned int ms_)
{
    if (ms_ == 0)
        return 0;
#if defined ZMQ_HAVE_WINDOWS
    Sleep (ms_ > 0 ? ms_ : INFINITE);
    return 0;
#elif defined ZMQ_HAVE_ANDROID
    usleep (ms_ * 1000);
    return 0;
#else
    return usleep (ms_ * 1000);
#endif
}

// Helper to wait on close(), for non-blocking sockets, until it completes
// If EAGAIN is received, will sleep briefly (1-100ms) then try again, until
// the overall timeout is reached.
//
static int close_wait_ms (int fd_, unsigned int max_ms_ = 2000)
{
    unsigned int ms_so_far = 0;
    unsigned int step_ms   = max_ms_ / 10;
    if (step_ms < 1)
        step_ms = 1;
    if (step_ms > 100)
        step_ms = 100;

    int rc = 0;       // do not sleep on first attempt
    do {
        if (rc == -1 && errno == EAGAIN) {
            sleep_ms (step_ms);
            ms_so_far += step_ms;
        }
        rc = close (fd_);
    } while (ms_so_far < max_ms_ && rc == -1 && errno == EAGAIN);

    return rc;
}
#endif

zmq::signaler_t::signaler_t ()
{
    //  Create the socketpair for signaling.
    if (make_fdpair (&r, &w) == 0) {
        unblock_socket (w);
        unblock_socket (r);
    }
#ifdef HAVE_FORK
    pid = getpid ();
#endif
}

// This might get run after some part of construction failed, leaving one or
// both of r and w retired_fd.
zmq::signaler_t::~signaler_t ()
{
#if defined ZMQ_HAVE_EVENTFD
    if (r == retired_fd) return;
    int rc = close_wait_ms (r);
    errno_assert (rc == 0);
#elif defined ZMQ_HAVE_WINDOWS
    if (w != retired_fd) {
        const struct linger so_linger = { 1, 0 };
        int rc = setsockopt (w, SOL_SOCKET, SO_LINGER,
            (const char *) &so_linger, sizeof so_linger);
        //  Only check shutdown if WSASTARTUP was previously done
        if (rc == 0 || WSAGetLastError () != WSANOTINITIALISED) {
            wsa_assert (rc != SOCKET_ERROR);
            rc = closesocket (w);
            wsa_assert (rc != SOCKET_ERROR);
            if (r == retired_fd) return;
            rc = closesocket (r);
            wsa_assert (rc != SOCKET_ERROR);
        }
    }
#else
    if (w != retired_fd) {
        int rc = close_wait_ms (w);
        errno_assert (rc == 0);
    }
    if (r != retired_fd) {
        int rc = close_wait_ms (r);
        errno_assert (rc == 0);
    }
#endif
}

zmq::fd_t zmq::signaler_t::get_fd () const
{
    return r;
}

void zmq::signaler_t::send ()
{
#if defined HAVE_FORK
    if (unlikely (pid != getpid ())) {
        //printf("Child process %d signaler_t::send returning without sending #1\n", getpid());
        return; // do not send anything in forked child context
    }
#endif
#if defined ZMQ_HAVE_EVENTFD
    const uint64_t inc = 1;
    ssize_t sz = write (w, &inc, sizeof (inc));
    errno_assert (sz == sizeof (inc));
#elif defined ZMQ_HAVE_WINDOWS
    unsigned char dummy = 0;
    while (true) {
        int nbytes = ::send (w, (char*) &dummy, sizeof (dummy), 0);
        wsa_assert (nbytes != SOCKET_ERROR);
        if (unlikely (nbytes == SOCKET_ERROR))
            continue;
        zmq_assert (nbytes == sizeof (dummy));
        break;
    }
#else
    unsigned char dummy = 0;
    while (true) {
        ssize_t nbytes = ::send (w, &dummy, sizeof (dummy), 0);
        if (unlikely (nbytes == -1 && errno == EINTR))
            continue;
#if defined(HAVE_FORK)
        if (unlikely (pid != getpid ())) {
            //printf("Child process %d signaler_t::send returning without sending #2\n", getpid());
            errno = EINTR;
            break;
        }
#endif
        zmq_assert (nbytes == sizeof dummy);
        break;
    }
#endif
}

int zmq::signaler_t::wait (int timeout_)
{
#ifdef HAVE_FORK
    if (unlikely (pid != getpid ())) {
        // we have forked and the file descriptor is closed. Emulate an interrupt
        // response.
        //printf("Child process %d signaler_t::wait returning simulating interrupt #1\n", getpid());
        errno = EINTR;
        return -1;
    }
#endif

#ifdef ZMQ_POLL_BASED_ON_POLL
    struct pollfd pfd;
    pfd.fd = r;
    pfd.events = POLLIN;
    int rc = poll (&pfd, 1, timeout_);
    if (unlikely (rc < 0)) {
        errno_assert (errno == EINTR);
        return -1;
    }
    else
    if (unlikely (rc == 0)) {
        errno = EAGAIN;
        return -1;
    }
#ifdef HAVE_FORK
    else
    if (unlikely (pid != getpid ())) {
        // we have forked and the file descriptor is closed. Emulate an interrupt
        // response.
        //printf("Child process %d signaler_t::wait returning simulating interrupt #2\n", getpid());
        errno = EINTR;
        return -1;
    }
#endif
    zmq_assert (rc == 1);
    zmq_assert (pfd.revents & POLLIN);
    return 0;

#elif defined ZMQ_POLL_BASED_ON_SELECT

    fd_set fds;
    FD_ZERO (&fds);
    FD_SET (r, &fds);
    struct timeval timeout;
    if (timeout_ >= 0) {
        timeout.tv_sec = timeout_ / 1000;
        timeout.tv_usec = timeout_ % 1000 * 1000;
    }
#ifdef ZMQ_HAVE_WINDOWS
    int rc = select (0, &fds, NULL, NULL,
        timeout_ >= 0 ? &timeout : NULL);
    wsa_assert (rc != SOCKET_ERROR);
#else
    int rc = select (r + 1, &fds, NULL, NULL,
        timeout_ >= 0 ? &timeout : NULL);
    if (unlikely (rc < 0)) {
        errno_assert (errno == EINTR);
        return -1;
    }
#endif
    if (unlikely (rc == 0)) {
        errno = EAGAIN;
        return -1;
    }
    zmq_assert (rc == 1);
    return 0;

#else
#error
#endif
}

void zmq::signaler_t::recv ()
{
    //  Attempt to read a signal.
#if defined ZMQ_HAVE_EVENTFD
    uint64_t dummy;
    ssize_t sz = read (r, &dummy, sizeof (dummy));
    errno_assert (sz == sizeof (dummy));

    //  If we accidentally grabbed the next signal(s) along with the current
    //  one, return it back to the eventfd object.
    if (unlikely (dummy > 1)) {
        const uint64_t inc = dummy - 1;
        ssize_t sz2 = write (w, &inc, sizeof (inc));
        errno_assert (sz2 == sizeof (inc));
        return;
    }

    zmq_assert (dummy == 1);
#else
    unsigned char dummy;
#if defined ZMQ_HAVE_WINDOWS
    int nbytes = ::recv (r, (char *) &dummy, sizeof (dummy), 0);
    wsa_assert (nbytes != SOCKET_ERROR);
#else
    ssize_t nbytes = ::recv (r, &dummy, sizeof (dummy), 0);
    errno_assert (nbytes >= 0);
#endif
    zmq_assert (nbytes == sizeof (dummy));
    zmq_assert (dummy == 0);
#endif
}

int zmq::signaler_t::recv_failable ()
{
    //  Attempt to read a signal.
#if defined ZMQ_HAVE_EVENTFD
    uint64_t dummy;
    ssize_t sz = read (r, &dummy, sizeof (dummy));
    if (sz == -1) {
        errno_assert (errno == EAGAIN);
        return -1;
    }
    else {
        errno_assert (sz == sizeof (dummy));

        //  If we accidentally grabbed the next signal(s) along with the current
        //  one, return it back to the eventfd object.
        if (unlikely (dummy > 1)) {
            const uint64_t inc = dummy - 1;
            ssize_t sz2 = write (w, &inc, sizeof (inc));
            errno_assert (sz2 == sizeof (inc));
            return 0;
        }

        zmq_assert (dummy == 1);
    }
#else
    unsigned char dummy;
#if defined ZMQ_HAVE_WINDOWS
    int nbytes = ::recv (r, (char *) &dummy, sizeof (dummy), 0);
    if (nbytes == SOCKET_ERROR) {
        const int last_error = WSAGetLastError();
        if (last_error == WSAEWOULDBLOCK) {
            errno = EAGAIN;
            return -1;
        }
        wsa_assert (last_error == WSAEWOULDBLOCK);
    }
#else
    ssize_t nbytes = ::recv (r, &dummy, sizeof (dummy), 0);
    if (nbytes == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            errno = EAGAIN;
            return -1;
        }
        errno_assert (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR);
    }
#endif
    zmq_assert (nbytes == sizeof (dummy));
    zmq_assert (dummy == 0);
#endif
    return 0;
}

#ifdef HAVE_FORK
void zmq::signaler_t::forked ()
{
    //  Close file descriptors created in the parent and create new pair
    close (r);
    close (w);
    make_fdpair (&r, &w);
}
#endif

//  Returns -1 if we could not make the socket pair successfully
int zmq::signaler_t::make_fdpair (fd_t *r_, fd_t *w_)
{
#if defined ZMQ_HAVE_EVENTFD
    int flags = 0;
#if defined ZMQ_HAVE_EVENTFD_CLOEXEC
    //  Setting this option result in sane behaviour when exec() functions
    //  are used. Old sockets are closed and don't block TCP ports, avoid
    //  leaks, etc.
    flags |= EFD_CLOEXEC;
#endif
    fd_t fd = eventfd (0, flags);
    if (fd == -1) {
        errno_assert (errno == ENFILE || errno == EMFILE);
        *w_ = *r_ = -1;
        return -1;
    }
    else {
        *w_ = *r_ = fd;
        return 0;
    }

#elif defined ZMQ_HAVE_WINDOWS
#   if !defined _WIN32_WCE
    //  Windows CE does not manage security attributes
    SECURITY_DESCRIPTOR sd;
    SECURITY_ATTRIBUTES sa;
    memset (&sd, 0, sizeof sd);
    memset (&sa, 0, sizeof sa);

    InitializeSecurityDescriptor (&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl (&sd, TRUE, 0, FALSE);

    sa.nLength = sizeof (SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = &sd;
#   endif

    //  This function has to be in a system-wide critical section so that
    //  two instances of the library don't accidentally create signaler
    //  crossing the process boundary.
    //  We'll use named event object to implement the critical section.
    //  Note that if the event object already exists, the CreateEvent requests
    //  EVENT_ALL_ACCESS access right. If this fails, we try to open
    //  the event object asking for SYNCHRONIZE access only.
    HANDLE sync = NULL;

    //  Create critical section only if using fixed signaler port
    //  Use problematic Event implementation for compatibility if using old port 5905.
    //  Otherwise use Mutex implementation.
    int event_signaler_port = 5905;

    if (signaler_port == event_signaler_port) {
#       if !defined _WIN32_WCE
        sync = CreateEventW (&sa, FALSE, TRUE, L"Global\\zmq-signaler-port-sync");
#       else
        sync = CreateEventW (NULL, FALSE, TRUE, L"Global\\zmq-signaler-port-sync");
#       endif
        if (sync == NULL && GetLastError () == ERROR_ACCESS_DENIED)
            sync = OpenEventW (SYNCHRONIZE | EVENT_MODIFY_STATE,
                              FALSE, L"Global\\zmq-signaler-port-sync");

        win_assert (sync != NULL);
    }
    else
    if (signaler_port != 0) {
        wchar_t mutex_name [MAX_PATH];
#       ifdef __MINGW32__
        _snwprintf (mutex_name, MAX_PATH, L"Global\\zmq-signaler-port-%d", signaler_port);
#       else
        swprintf (mutex_name, MAX_PATH, L"Global\\zmq-signaler-port-%d", signaler_port);
#       endif

#       if !defined _WIN32_WCE
        sync = CreateMutexW (&sa, FALSE, mutex_name);
#       else
        sync = CreateMutexW (NULL, FALSE, mutex_name);
#       endif
        if (sync == NULL && GetLastError () == ERROR_ACCESS_DENIED)
            sync = OpenMutexW (SYNCHRONIZE, FALSE, mutex_name);

        win_assert (sync != NULL);
    }

    //  Windows has no 'socketpair' function. CreatePipe is no good as pipe
    //  handles cannot be polled on. Here we create the socketpair by hand.
    *w_ = INVALID_SOCKET;
    *r_ = INVALID_SOCKET;

    //  Create listening socket.
    SOCKET listener;
    listener = open_socket (AF_INET, SOCK_STREAM, 0);
    wsa_assert (listener != INVALID_SOCKET);

    //  Set SO_REUSEADDR and TCP_NODELAY on listening socket.
    BOOL so_reuseaddr = 1;
    int rc = setsockopt (listener, SOL_SOCKET, SO_REUSEADDR,
        (char *) &so_reuseaddr, sizeof so_reuseaddr);
    wsa_assert (rc != SOCKET_ERROR);
    BOOL tcp_nodelay = 1;
    rc = setsockopt (listener, IPPROTO_TCP, TCP_NODELAY,
        (char *) &tcp_nodelay, sizeof tcp_nodelay);
    wsa_assert (rc != SOCKET_ERROR);

    //  Init sockaddr to signaler port.
    struct sockaddr_in addr;
    memset (&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
    addr.sin_port = htons (signaler_port);

    //  Create the writer socket.
    *w_ = open_socket (AF_INET, SOCK_STREAM, 0);
    wsa_assert (*w_ != INVALID_SOCKET);

    //  Set TCP_NODELAY on writer socket.
    rc = setsockopt (*w_, IPPROTO_TCP, TCP_NODELAY,
        (char *) &tcp_nodelay, sizeof tcp_nodelay);
    wsa_assert (rc != SOCKET_ERROR);

    if (sync != NULL) {
        //  Enter the critical section.
        DWORD dwrc = WaitForSingleObject (sync, INFINITE);
        zmq_assert (dwrc == WAIT_OBJECT_0 || dwrc == WAIT_ABANDONED);
    }

    //  Bind listening socket to signaler port.
    rc = bind (listener, (const struct sockaddr *) &addr, sizeof addr);

    if (rc != SOCKET_ERROR && signaler_port == 0) {
        //  Retrieve ephemeral port number
        int addrlen = sizeof addr;
        rc = getsockname (listener, (struct sockaddr *) &addr, &addrlen);
    }

    //  Listen for incoming connections.
    if (rc != SOCKET_ERROR)
        rc = listen (listener, 1);

    //  Connect writer to the listener.
    if (rc != SOCKET_ERROR)
        rc = connect (*w_, (struct sockaddr *) &addr, sizeof addr);

    //  Accept connection from writer.
    if (rc != SOCKET_ERROR)
        *r_ = accept (listener, NULL, NULL);

    //  Send/receive large chunk to work around TCP slow start
    //  This code is a workaround for #1608
    if (*r_ != INVALID_SOCKET) {
        size_t dummy_size = 1024 * 1024;        //  1M to overload default receive buffer
        unsigned char *dummy = (unsigned char *) malloc (dummy_size);
        int still_to_send = (int) dummy_size;
        int still_to_recv = (int) dummy_size;
        while (still_to_send || still_to_recv) {
            int nbytes;
            if (still_to_send > 0) {
                nbytes = ::send (*w_, (char *) (dummy + dummy_size - still_to_send), still_to_send, 0);
                wsa_assert (nbytes != SOCKET_ERROR);
                still_to_send -= nbytes;
            }
            nbytes = ::recv (*r_, (char *) (dummy + dummy_size - still_to_recv), still_to_recv, 0);
            wsa_assert (nbytes != SOCKET_ERROR);
            still_to_recv -= nbytes;
        }
        free (dummy);
    }

    //  Save errno if error occurred in bind/listen/connect/accept.
    int saved_errno = 0;
    if (*r_ == INVALID_SOCKET)
        saved_errno = WSAGetLastError ();

    //  We don't need the listening socket anymore. Close it.
    rc = closesocket (listener);
    wsa_assert(rc != SOCKET_ERROR);

    if (sync != NULL) {
        //  Exit the critical section.
        BOOL brc;
        if (signaler_port == event_signaler_port)
            brc = SetEvent (sync);
        else
            brc = ReleaseMutex (sync);
        win_assert (brc != 0);

        //  Release the kernel object
        brc = CloseHandle (sync);
        win_assert (brc != 0);
    }

    if (*r_ != INVALID_SOCKET) {
#   if !defined _WIN32_WCE
        //  On Windows, preventing sockets to be inherited by child processes.
        BOOL brc = SetHandleInformation ((HANDLE) *r_, HANDLE_FLAG_INHERIT, 0);
        win_assert (brc);
#   endif
        return 0;
    }
    else {
        //  Cleanup writer if connection failed
        if (*w_ != INVALID_SOCKET) {
            rc = closesocket (*w_);
            wsa_assert (rc != SOCKET_ERROR);
            *w_ = INVALID_SOCKET;
        }
        //  Set errno from saved value
        errno = wsa_error_to_errno (saved_errno);
        return -1;
    }

#elif defined ZMQ_HAVE_OPENVMS

    //  Whilst OpenVMS supports socketpair - it maps to AF_INET only.  Further,
    //  it does not set the socket options TCP_NODELAY and TCP_NODELACK which
    //  can lead to performance problems.
    //
    //  The bug will be fixed in V5.6 ECO4 and beyond.  In the meantime, we'll
    //  create the socket pair manually.
    struct sockaddr_in lcladdr;
    memset (&lcladdr, 0, sizeof lcladdr);
    lcladdr.sin_family = AF_INET;
    lcladdr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
    lcladdr.sin_port = 0;

    int listener = open_socket (AF_INET, SOCK_STREAM, 0);
    errno_assert (listener != -1);

    int on = 1;
    int rc = setsockopt (listener, IPPROTO_TCP, TCP_NODELAY, &on, sizeof on);
    errno_assert (rc != -1);

    rc = setsockopt (listener, IPPROTO_TCP, TCP_NODELACK, &on, sizeof on);
    errno_assert (rc != -1);

    rc = bind (listener, (struct sockaddr *) &lcladdr, sizeof lcladdr);
    errno_assert (rc != -1);

    socklen_t lcladdr_len = sizeof lcladdr;

    rc = getsockname (listener, (struct sockaddr *) &lcladdr, &lcladdr_len);
    errno_assert (rc != -1);

    rc = listen (listener, 1);
    errno_assert (rc != -1);

    *w_ = open_socket (AF_INET, SOCK_STREAM, 0);
    errno_assert (*w_ != -1);

    rc = setsockopt (*w_, IPPROTO_TCP, TCP_NODELAY, &on, sizeof on);
    errno_assert (rc != -1);

    rc = setsockopt (*w_, IPPROTO_TCP, TCP_NODELACK, &on, sizeof on);
    errno_assert (rc != -1);

    rc = connect (*w_, (struct sockaddr *) &lcladdr, sizeof lcladdr);
    errno_assert (rc != -1);

    *r_ = accept (listener, NULL, NULL);
    errno_assert (*r_ != -1);

    close (listener);

    return 0;

#else
    // All other implementations support socketpair()
    int sv [2];
    int type = SOCK_STREAM;
    //  Setting this option result in sane behaviour when exec() functions
    //  are used. Old sockets are closed and don't block TCP ports, avoid
    //  leaks, etc.
#if defined ZMQ_HAVE_SOCK_CLOEXEC
    type |= SOCK_CLOEXEC;
#endif
    int rc = socketpair (AF_UNIX, type, 0, sv);
    if (rc == -1) {
        errno_assert (errno == ENFILE || errno == EMFILE);
        *w_ = *r_ = -1;
        return -1;
    }
    else {
        //  If there's no SOCK_CLOEXEC, let's try the second best option. Note that
        //  race condition can cause socket not to be closed (if fork happens
        //  between socket creation and this point).
#if !defined ZMQ_HAVE_SOCK_CLOEXEC && defined FD_CLOEXEC
        rc = fcntl (sv [0], F_SETFD, FD_CLOEXEC);
        errno_assert (rc != -1);
        rc = fcntl (sv [1], F_SETFD, FD_CLOEXEC);
        errno_assert (rc != -1);
#endif
        *w_ = sv [0];
        *r_ = sv [1];
        return 0;
    }
#endif
}
