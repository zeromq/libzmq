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
#include "macros.hpp"
#include "config.hpp"
#include "address.hpp"

#if !defined ZMQ_HAVE_WINDOWS
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#else
#include "tcp.hpp"
#endif

#if defined ZMQ_HAVE_OPENVMS || defined ZMQ_HAVE_VXWORKS
#include <ioctl.h>
#endif

#if defined ZMQ_HAVE_VXWORKS
#include <unistd.h>
#include <sockLib.h>
#include <ioLib.h>
#endif

#if defined ZMQ_HAVE_EVENTFD
#include <sys/eventfd.h>
#endif

#if defined ZMQ_HAVE_OPENPGM
#ifdef ZMQ_HAVE_WINDOWS
#define __PGM_WININT_H__
#endif

#include <pgm/pgm.h>
#endif

#ifdef __APPLE__
#include <TargetConditionals.h>
#endif

zmq::fd_t zmq::open_socket (int domain_, int type_, int protocol_)
{
    int rc;

    //  Setting this option result in sane behaviour when exec() functions
    //  are used. Old sockets are closed and don't block TCP ports etc.
#if defined ZMQ_HAVE_SOCK_CLOEXEC
    type_ |= SOCK_CLOEXEC;
#endif

#if defined ZMQ_HAVE_WINDOWS && defined WSA_FLAG_NO_HANDLE_INHERIT
    // if supported, create socket with WSA_FLAG_NO_HANDLE_INHERIT, such that
    // the race condition in making it non-inheritable later is avoided
    const fd_t s =
      WSASocket (domain_, type_, protocol_, NULL, 0,
                 WSA_FLAG_OVERLAPPED || WSA_FLAG_NO_HANDLE_INHERIT);
#else
    const fd_t s = socket (domain_, type_, protocol_);
#endif
    if (s == retired_fd) {
#ifdef ZMQ_HAVE_WINDOWS
        errno = wsa_error_to_errno (WSAGetLastError ());
#endif
        return retired_fd;
    }

    make_socket_noninheritable (s);

    //  Socket is not yet connected so EINVAL is not a valid networking error
    rc = zmq::set_nosigpipe (s);
    errno_assert (rc == 0);

    return s;
}

void zmq::unblock_socket (fd_t s_)
{
#if defined ZMQ_HAVE_WINDOWS
    u_long nonblock = 1;
    int rc = ioctlsocket (s_, FIONBIO, &nonblock);
    wsa_assert (rc != SOCKET_ERROR);
#elif defined ZMQ_HAVE_OPENVMS || defined ZMQ_HAVE_VXWORKS
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
    LIBZMQ_UNUSED (s_);

#if defined IPV6_V6ONLY && !defined ZMQ_HAVE_OPENBSD                           \
  && !defined ZMQ_HAVE_DRAGONFLY
#ifdef ZMQ_HAVE_WINDOWS
    DWORD flag = 0;
#else
    int flag = 0;
#endif
    int rc = setsockopt (s_, IPPROTO_IPV6, IPV6_V6ONLY,
                         reinterpret_cast<char *> (&flag), sizeof (flag));
#ifdef ZMQ_HAVE_WINDOWS
    wsa_assert (rc != SOCKET_ERROR);
#else
    errno_assert (rc == 0);
#endif
#endif
}

int zmq::get_peer_ip_address (fd_t sockfd_, std::string &ip_addr_)
{
    struct sockaddr_storage ss;

    zmq_socklen_t addrlen =
      get_socket_address (sockfd_, socket_end_remote, &ss);

    if (addrlen == 0) {
#ifdef ZMQ_HAVE_WINDOWS
        const int last_error = WSAGetLastError ();
        wsa_assert (last_error != WSANOTINITIALISED && last_error != WSAEFAULT
                    && last_error != WSAEINPROGRESS
                    && last_error != WSAENOTSOCK);
#elif !defined(TARGET_OS_IPHONE) || !TARGET_OS_IPHONE
        errno_assert (errno != EBADF && errno != EFAULT && errno != ENOTSOCK);
#else
        errno_assert (errno != EFAULT && errno != ENOTSOCK);
#endif
        return 0;
    }

    char host[NI_MAXHOST];
    int rc = getnameinfo (reinterpret_cast<struct sockaddr *> (&ss), addrlen,
                          host, sizeof host, NULL, 0, NI_NUMERICHOST);
    if (rc != 0)
        return 0;

    ip_addr_ = host;

    union
    {
        struct sockaddr sa;
        struct sockaddr_storage sa_stor;
    } u;

    u.sa_stor = ss;
    return static_cast<int> (u.sa.sa_family);
}

void zmq::set_ip_type_of_service (fd_t s_, int iptos_)
{
    int rc = setsockopt (s_, IPPROTO_IP, IP_TOS,
                         reinterpret_cast<char *> (&iptos_), sizeof (iptos_));

#ifdef ZMQ_HAVE_WINDOWS
    wsa_assert (rc != SOCKET_ERROR);
#else
    errno_assert (rc == 0);
#endif

    //  Windows and Hurd do not support IPV6_TCLASS
#if !defined(ZMQ_HAVE_WINDOWS) && defined(IPV6_TCLASS)
    rc = setsockopt (s_, IPPROTO_IPV6, IPV6_TCLASS,
                     reinterpret_cast<char *> (&iptos_), sizeof (iptos_));

    //  If IPv6 is not enabled ENOPROTOOPT will be returned on Linux and
    //  EINVAL on OSX
    if (rc == -1) {
        errno_assert (errno == ENOPROTOOPT || errno == EINVAL);
    }
#endif
}

int zmq::set_nosigpipe (fd_t s_)
{
#ifdef SO_NOSIGPIPE
    //  Make sure that SIGPIPE signal is not generated when writing to a
    //  connection that was already closed by the peer.
    //  As per POSIX spec, EINVAL will be returned if the socket was valid but
    //  the connection has been reset by the peer. Return an error so that the
    //  socket can be closed and the connection retried if necessary.
    int set = 1;
    int rc = setsockopt (s_, SOL_SOCKET, SO_NOSIGPIPE, &set, sizeof (int));
    if (rc != 0 && errno == EINVAL)
        return -1;
    errno_assert (rc == 0);
#else
    LIBZMQ_UNUSED (s_);
#endif

    return 0;
}

int zmq::bind_to_device (fd_t s_, const std::string &bound_device_)
{
#ifdef ZMQ_HAVE_SO_BINDTODEVICE
    int rc = setsockopt (s_, SOL_SOCKET, SO_BINDTODEVICE,
                         bound_device_.c_str (), bound_device_.length ());
    if (rc != 0) {
        assert_success_or_recoverable (s_, rc);
        return -1;
    } else {
        return 0;
    }
#else
    LIBZMQ_UNUSED (s_);
    LIBZMQ_UNUSED (bound_device_);

    errno = ENOTSUP;
    return -1;
#endif
}

bool zmq::initialize_network ()
{
#if defined ZMQ_HAVE_OPENPGM

    //  Init PGM transport. Ensure threading and timer are enabled. Find PGM
    //  protocol ID. Note that if you want to use gettimeofday and sleep for
    //  openPGM timing, set environment variables PGM_TIMER to "GTOD" and
    //  PGM_SLEEP to "USLEEP".
    pgm_error_t *pgm_error = NULL;
    const bool ok = pgm_init (&pgm_error);
    if (ok != TRUE) {
        //  Invalid parameters don't set pgm_error_t
        zmq_assert (pgm_error != NULL);
        if (pgm_error->domain == PGM_ERROR_DOMAIN_TIME
            && (pgm_error->code == PGM_ERROR_FAILED)) {
            //  Failed to access RTC or HPET device.
            pgm_error_free (pgm_error);
            errno = EINVAL;
            return false;
        }

        //  PGM_ERROR_DOMAIN_ENGINE: WSAStartup errors or missing WSARecvMsg.
        zmq_assert (false);
    }
#endif

#ifdef ZMQ_HAVE_WINDOWS
    //  Intialise Windows sockets. Note that WSAStartup can be called multiple
    //  times given that WSACleanup will be called for each WSAStartup.

    WORD version_requested = MAKEWORD (2, 2);
    WSADATA wsa_data;
    int rc = WSAStartup (version_requested, &wsa_data);
    zmq_assert (rc == 0);
    zmq_assert (LOBYTE (wsa_data.wVersion) == 2
                && HIBYTE (wsa_data.wVersion) == 2);
#endif

    return true;
}

void zmq::shutdown_network ()
{
#ifdef ZMQ_HAVE_WINDOWS
    //  On Windows, uninitialise socket layer.
    int rc = WSACleanup ();
    wsa_assert (rc != SOCKET_ERROR);
#endif

#if defined ZMQ_HAVE_OPENPGM
    //  Shut down the OpenPGM library.
    if (pgm_shutdown () != TRUE)
        zmq_assert (false);
#endif
}

#if defined ZMQ_HAVE_WINDOWS
static void tune_socket (const SOCKET socket_)
{
    BOOL tcp_nodelay = 1;
    int rc =
      setsockopt (socket_, IPPROTO_TCP, TCP_NODELAY,
                  reinterpret_cast<char *> (&tcp_nodelay), sizeof tcp_nodelay);
    wsa_assert (rc != SOCKET_ERROR);

    zmq::tcp_tune_loopback_fast_path (socket_);
}
#endif

int zmq::make_fdpair (fd_t *r_, fd_t *w_)
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
    } else {
        *w_ = *r_ = fd;
        return 0;
    }

#elif defined ZMQ_HAVE_WINDOWS
#if !defined _WIN32_WCE && !defined ZMQ_HAVE_WINDOWS_UWP
    //  Windows CE does not manage security attributes
    SECURITY_DESCRIPTOR sd;
    SECURITY_ATTRIBUTES sa;
    memset (&sd, 0, sizeof sd);
    memset (&sa, 0, sizeof sa);

    InitializeSecurityDescriptor (&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl (&sd, TRUE, 0, FALSE);

    sa.nLength = sizeof (SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = &sd;
#endif

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
#if !defined _WIN32_WCE && !defined ZMQ_HAVE_WINDOWS_UWP
        sync =
          CreateEventW (&sa, FALSE, TRUE, L"Global\\zmq-signaler-port-sync");
#else
        sync =
          CreateEventW (NULL, FALSE, TRUE, L"Global\\zmq-signaler-port-sync");
#endif
        if (sync == NULL && GetLastError () == ERROR_ACCESS_DENIED)
            sync = OpenEventW (SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE,
                               L"Global\\zmq-signaler-port-sync");

        win_assert (sync != NULL);
    } else if (signaler_port != 0) {
        wchar_t mutex_name[MAX_PATH];
#ifdef __MINGW32__
        _snwprintf (mutex_name, MAX_PATH, L"Global\\zmq-signaler-port-%d",
                    signaler_port);
#else
        swprintf (mutex_name, MAX_PATH, L"Global\\zmq-signaler-port-%d",
                  signaler_port);
#endif

#if !defined _WIN32_WCE && !defined ZMQ_HAVE_WINDOWS_UWP
        sync = CreateMutexW (&sa, FALSE, mutex_name);
#else
        sync = CreateMutexW (NULL, FALSE, mutex_name);
#endif
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
                         reinterpret_cast<char *> (&so_reuseaddr),
                         sizeof so_reuseaddr);
    wsa_assert (rc != SOCKET_ERROR);

    tune_socket (listener);

    //  Init sockaddr to signaler port.
    struct sockaddr_in addr;
    memset (&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
    addr.sin_port = htons (signaler_port);

    //  Create the writer socket.
    *w_ = open_socket (AF_INET, SOCK_STREAM, 0);
    wsa_assert (*w_ != INVALID_SOCKET);

    if (sync != NULL) {
        //  Enter the critical section.
        DWORD dwrc = WaitForSingleObject (sync, INFINITE);
        zmq_assert (dwrc == WAIT_OBJECT_0 || dwrc == WAIT_ABANDONED);
    }

    //  Bind listening socket to signaler port.
    rc = bind (listener, reinterpret_cast<const struct sockaddr *> (&addr),
               sizeof addr);

    if (rc != SOCKET_ERROR && signaler_port == 0) {
        //  Retrieve ephemeral port number
        int addrlen = sizeof addr;
        rc = getsockname (listener, reinterpret_cast<struct sockaddr *> (&addr),
                          &addrlen);
    }

    //  Listen for incoming connections.
    if (rc != SOCKET_ERROR)
        rc = listen (listener, 1);

    //  Connect writer to the listener.
    if (rc != SOCKET_ERROR)
        rc = connect (*w_, reinterpret_cast<struct sockaddr *> (&addr),
                      sizeof addr);

    //  Set TCP_NODELAY on writer socket.
    tune_socket (*w_);

    //  Accept connection from writer.
    if (rc != SOCKET_ERROR)
        *r_ = accept (listener, NULL, NULL);

    //  Send/receive large chunk to work around TCP slow start
    //  This code is a workaround for #1608
    if (*r_ != INVALID_SOCKET) {
        size_t dummy_size =
          1024 * 1024; //  1M to overload default receive buffer
        unsigned char *dummy =
          static_cast<unsigned char *> (malloc (dummy_size));
        wsa_assert (dummy);

        int still_to_send = static_cast<int> (dummy_size);
        int still_to_recv = static_cast<int> (dummy_size);
        while (still_to_send || still_to_recv) {
            int nbytes;
            if (still_to_send > 0) {
                nbytes = ::send (
                  *w_,
                  reinterpret_cast<char *> (dummy + dummy_size - still_to_send),
                  still_to_send, 0);
                wsa_assert (nbytes != SOCKET_ERROR);
                still_to_send -= nbytes;
            }
            nbytes = ::recv (
              *r_,
              reinterpret_cast<char *> (dummy + dummy_size - still_to_recv),
              still_to_recv, 0);
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
    wsa_assert (rc != SOCKET_ERROR);

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
        make_socket_noninheritable (*r_);
        return 0;
    }
    //  Cleanup writer if connection failed
    if (*w_ != INVALID_SOCKET) {
        rc = closesocket (*w_);
        wsa_assert (rc != SOCKET_ERROR);
        *w_ = INVALID_SOCKET;
    }
    //  Set errno from saved value
    errno = wsa_error_to_errno (saved_errno);
    return -1;


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
#elif defined ZMQ_HAVE_VXWORKS
    struct sockaddr_in lcladdr;
    memset (&lcladdr, 0, sizeof lcladdr);
    lcladdr.sin_family = AF_INET;
    lcladdr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
    lcladdr.sin_port = 0;

    int listener = open_socket (AF_INET, SOCK_STREAM, 0);
    errno_assert (listener != -1);

    int on = 1;
    int rc =
      setsockopt (listener, IPPROTO_TCP, TCP_NODELAY, (char *) &on, sizeof on);
    errno_assert (rc != -1);

    rc = bind (listener, (struct sockaddr *) &lcladdr, sizeof lcladdr);
    errno_assert (rc != -1);

    socklen_t lcladdr_len = sizeof lcladdr;

    rc = getsockname (listener, (struct sockaddr *) &lcladdr,
                      (int *) &lcladdr_len);
    errno_assert (rc != -1);

    rc = listen (listener, 1);
    errno_assert (rc != -1);

    *w_ = open_socket (AF_INET, SOCK_STREAM, 0);
    errno_assert (*w_ != -1);

    rc = setsockopt (*w_, IPPROTO_TCP, TCP_NODELAY, (char *) &on, sizeof on);
    errno_assert (rc != -1);

    rc = connect (*w_, (struct sockaddr *) &lcladdr, sizeof lcladdr);
    errno_assert (rc != -1);

    *r_ = accept (listener, NULL, NULL);
    errno_assert (*r_ != -1);

    close (listener);

    return 0;
#else
    // All other implementations support socketpair()
    int sv[2];
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
    } else {
        make_socket_noninheritable (sv[0]);
        make_socket_noninheritable (sv[1]);

        *w_ = sv[0];
        *r_ = sv[1];
        return 0;
    }
#endif
}

void zmq::make_socket_noninheritable (fd_t sock_)
{
#if defined ZMQ_HAVE_WINDOWS && !defined _WIN32_WCE                            \
  && !defined ZMQ_HAVE_WINDOWS_UWP
    //  On Windows, preventing sockets to be inherited by child processes.
    const BOOL brc = SetHandleInformation (reinterpret_cast<HANDLE> (sock_),
                                           HANDLE_FLAG_INHERIT, 0);
    win_assert (brc);
#elif (!defined ZMQ_HAVE_SOCK_CLOEXEC || !defined HAVE_ACCEPT4)                \
  && defined FD_CLOEXEC
    //  If there 's no SOCK_CLOEXEC, let's try the second best option.
    //  Race condition can cause socket not to be closed (if fork happens
    //  between accept and this point).
    const int rc = fcntl (sock_, F_SETFD, FD_CLOEXEC);
    errno_assert (rc != -1);
#else
    LIBZMQ_UNUSED (sock_);
#endif
}

void zmq::assert_success_or_recoverable (zmq::fd_t s_, int rc_)
{
#ifdef ZMQ_HAVE_WINDOWS
    if (rc_ != SOCKET_ERROR) {
        return;
    }
#else
    if (rc_ != -1) {
        return;
    }
#endif

    //  Check whether an error occurred
    int err = 0;
#if defined ZMQ_HAVE_HPUX || defined ZMQ_HAVE_VXWORKS
    int len = sizeof err;
#else
    socklen_t len = sizeof err;
#endif

    int rc = getsockopt (s_, SOL_SOCKET, SO_ERROR,
                         reinterpret_cast<char *> (&err), &len);

    //  Assert if the error was caused by 0MQ bug.
    //  Networking problems are OK. No need to assert.
#ifdef ZMQ_HAVE_WINDOWS
    zmq_assert (rc == 0);
    if (err != 0) {
        wsa_assert (err == WSAECONNREFUSED || err == WSAECONNRESET
                    || err == WSAECONNABORTED || err == WSAEINTR
                    || err == WSAETIMEDOUT || err == WSAEHOSTUNREACH
                    || err == WSAENETUNREACH || err == WSAENETDOWN
                    || err == WSAENETRESET || err == WSAEACCES
                    || err == WSAEINVAL || err == WSAEADDRINUSE);
    }
#else
    //  Following code should handle both Berkeley-derived socket
    //  implementations and Solaris.
    if (rc == -1)
        err = errno;
    if (err != 0) {
        errno = err;
        errno_assert (errno == ECONNREFUSED || errno == ECONNRESET
                      || errno == ECONNABORTED || errno == EINTR
                      || errno == ETIMEDOUT || errno == EHOSTUNREACH
                      || errno == ENETUNREACH || errno == ENETDOWN
                      || errno == ENETRESET || errno == EINVAL);
    }
#endif
}
