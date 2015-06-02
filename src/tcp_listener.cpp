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

#include <new>

#include <string>
#include <stdio.h>

#include "platform.hpp"
#include "tcp_listener.hpp"
#include "stream_engine.hpp"
#include "io_thread.hpp"
#include "session_base.hpp"
#include "config.hpp"
#include "err.hpp"
#include "ip.hpp"
#include "tcp.hpp"
#include "socket_base.hpp"

#ifdef ZMQ_HAVE_WINDOWS
#include "windows.hpp"
#else
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#endif

#ifdef ZMQ_HAVE_OPENVMS
#include <ioctl.h>
#endif

zmq::tcp_listener_t::tcp_listener_t (io_thread_t *io_thread_,
      socket_base_t *socket_, const options_t &options_) :
    own_t (io_thread_, options_),
    io_object_t (io_thread_),
    s (retired_fd),
    socket (socket_)
{
}

zmq::tcp_listener_t::~tcp_listener_t ()
{
    zmq_assert (s == retired_fd);
}

void zmq::tcp_listener_t::process_plug ()
{
    //  Start polling for incoming connections.
    handle = add_fd (s);
    set_pollin (handle);
}

void zmq::tcp_listener_t::process_term (int linger_)
{
    rm_fd (handle);
    close ();
    own_t::process_term (linger_);
}

void zmq::tcp_listener_t::in_event ()
{
    fd_t fd = accept ();

    //  If connection was reset by the peer in the meantime, just ignore it.
    //  TODO: Handle specific errors like ENFILE/EMFILE etc.
    if (fd == retired_fd) {
        socket->event_accept_failed (endpoint, zmq_errno());
        return;
    }

    tune_tcp_socket (fd);
    tune_tcp_keepalives (fd, options.tcp_keepalive, options.tcp_keepalive_cnt, options.tcp_keepalive_idle, options.tcp_keepalive_intvl);

    // remember our fd for ZMQ_SRCFD in messages
    socket->set_fd(fd);

    //  Create the engine object for this connection.
    stream_engine_t *engine = new (std::nothrow)
        stream_engine_t (fd, options, endpoint);
    alloc_assert (engine);

    //  Choose I/O thread to run connecter in. Given that we are already
    //  running in an I/O thread, there must be at least one available.
    io_thread_t *io_thread = choose_io_thread (options.affinity);
    zmq_assert (io_thread);

    //  Create and launch a session object.
    session_base_t *session = session_base_t::create (io_thread, false, socket,
        options, NULL);
    errno_assert (session);
    session->inc_seqnum ();
    launch_child (session);
    send_attach (session, engine, false);
    socket->event_accepted (endpoint, fd);
}

void zmq::tcp_listener_t::close ()
{
    zmq_assert (s != retired_fd);
#ifdef ZMQ_HAVE_WINDOWS
    int rc = closesocket (s);
    wsa_assert (rc != SOCKET_ERROR);
#else
    int rc = ::close (s);
    errno_assert (rc == 0);
#endif
    socket->event_closed (endpoint, s);
    s = retired_fd;
}

int zmq::tcp_listener_t::get_address (std::string &addr_)
{
    // Get the details of the TCP socket
    struct sockaddr_storage ss;
#ifdef ZMQ_HAVE_HPUX
    int sl = sizeof (ss);
#else
    socklen_t sl = sizeof (ss);
#endif
    int rc = getsockname (s, (struct sockaddr *) &ss, &sl);

    if (rc != 0) {
        addr_.clear ();
        return rc;
    }

    tcp_address_t addr ((struct sockaddr *) &ss, sl);
    return addr.to_string (addr_);
}

int zmq::tcp_listener_t::set_address (const char *addr_)
{
    //  Convert the textual address into address structure.
    int rc = address.resolve (addr_, true, options.ipv6);
    if (rc != 0)
        return -1;

    //  Create a listening socket.
    s = open_socket (address.family (), SOCK_STREAM, IPPROTO_TCP);
#ifdef ZMQ_HAVE_WINDOWS
    if (s == INVALID_SOCKET)
        errno = wsa_error_to_errno (WSAGetLastError ());
#endif

    //  IPv6 address family not supported, try automatic downgrade to IPv4.
    if (address.family () == AF_INET6
    && errno == EAFNOSUPPORT
    && options.ipv6) {
        rc = address.resolve (addr_, true, true);
        if (rc != 0)
            return rc;
        s = ::socket (address.family (), SOCK_STREAM, IPPROTO_TCP);
    }

#ifdef ZMQ_HAVE_WINDOWS
    if (s == INVALID_SOCKET) {
        errno = wsa_error_to_errno (WSAGetLastError ());
        return -1;
    }
#if !defined _WIN32_WCE
    //  On Windows, preventing sockets to be inherited by child processes.
    BOOL brc = SetHandleInformation ((HANDLE) s, HANDLE_FLAG_INHERIT, 0);
    win_assert (brc);
#endif
#else
    if (s == -1)
        return -1;
#endif

    //  On some systems, IPv4 mapping in IPv6 sockets is disabled by default.
    //  Switch it on in such cases.
    if (address.family () == AF_INET6)
        enable_ipv4_mapping (s);

    // Set the IP Type-Of-Service for the underlying socket
    if (options.tos != 0)
        set_ip_type_of_service (s, options.tos);

    //  Set the socket buffer limits for the underlying socket.
    if (options.sndbuf != 0)
        set_tcp_send_buffer (s, options.sndbuf);
    if (options.rcvbuf != 0)
        set_tcp_receive_buffer (s, options.rcvbuf);

    //  Allow reusing of the address.
    int flag = 1;
#ifdef ZMQ_HAVE_WINDOWS
    rc = setsockopt (s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
        (const char*) &flag, sizeof (int));
    wsa_assert (rc != SOCKET_ERROR);
#else
    rc = setsockopt (s, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof (int));
    errno_assert (rc == 0);
#endif

    address.to_string (endpoint);

    //  Bind the socket to the network interface and port.
    rc = bind (s, address.addr (), address.addrlen ());
#ifdef ZMQ_HAVE_WINDOWS
    if (rc == SOCKET_ERROR) {
        errno = wsa_error_to_errno (WSAGetLastError ());
        goto error;
    }
#else
    if (rc != 0)
        goto error;
#endif

    //  Listen for incoming connections.
    rc = listen (s, options.backlog);
#ifdef ZMQ_HAVE_WINDOWS
    if (rc == SOCKET_ERROR) {
        errno = wsa_error_to_errno (WSAGetLastError ());
        goto error;
    }
#else
    if (rc != 0)
        goto error;
#endif

    socket->event_listening (endpoint, s);
    return 0;

error:
    int err = errno;
    close ();
    errno = err;
    return -1;
}

zmq::fd_t zmq::tcp_listener_t::accept ()
{
    //  The situation where connection cannot be accepted due to insufficient
    //  resources is considered valid and treated by ignoring the connection.
    //  Accept one connection and deal with different failure modes.
    zmq_assert (s != retired_fd);

    struct sockaddr_storage ss;
    memset (&ss, 0, sizeof (ss));
#ifdef ZMQ_HAVE_HPUX
    int ss_len = sizeof (ss);
#else
    socklen_t ss_len = sizeof (ss);
#endif
    fd_t sock = ::accept (s, (struct sockaddr *) &ss, &ss_len);

#ifdef ZMQ_HAVE_WINDOWS
    if (sock == INVALID_SOCKET) {
        wsa_assert (WSAGetLastError () == WSAEWOULDBLOCK ||
            WSAGetLastError () == WSAECONNRESET ||
            WSAGetLastError () == WSAEMFILE ||
            WSAGetLastError () == WSAENOBUFS);
        return retired_fd;
    }
#if !defined _WIN32_WCE
    //  On Windows, preventing sockets to be inherited by child processes.
    BOOL brc = SetHandleInformation ((HANDLE) sock, HANDLE_FLAG_INHERIT, 0);
    win_assert (brc);
#endif
#else
    if (sock == -1) {
        errno_assert (errno == EAGAIN || errno == EWOULDBLOCK ||
            errno == EINTR || errno == ECONNABORTED || errno == EPROTO ||
            errno == ENOBUFS || errno == ENOMEM || errno == EMFILE ||
            errno == ENFILE);
        return retired_fd;
    }
#endif

    //  Race condition can cause socket not to be closed (if fork happens
    //  between accept and this point).
#ifdef FD_CLOEXEC
    int rc = fcntl (sock, F_SETFD, FD_CLOEXEC);
    errno_assert (rc != -1);
#endif

    if (!options.tcp_accept_filters.empty ()) {
        bool matched = false;
        for (options_t::tcp_accept_filters_t::size_type i = 0; i != options.tcp_accept_filters.size (); ++i) {
            if (options.tcp_accept_filters[i].match_address ((struct sockaddr *) &ss, ss_len)) {
                matched = true;
                break;
            }
        }
        if (!matched) {
#ifdef ZMQ_HAVE_WINDOWS
            int rc = closesocket (sock);
            wsa_assert (rc != SOCKET_ERROR);
#else
            int rc = ::close (sock);
            errno_assert (rc == 0);
#endif
            return retired_fd;
        }
    }

    // Set the IP Type-Of-Service priority for this client socket
    if (options.tos != 0)
        set_ip_type_of_service (sock, options.tos);

    return sock;
}
