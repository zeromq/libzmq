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
#include <new>

#include <string>
#include <stdio.h>

#include "tcp_listener.hpp"
#include "io_thread.hpp"
#include "config.hpp"
#include "err.hpp"
#include "ip.hpp"
#include "tcp.hpp"
#include "socket_base.hpp"
#include "address.hpp"

#ifndef ZMQ_HAVE_WINDOWS
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#ifdef ZMQ_HAVE_VXWORKS
#include <sockLib.h>
#endif
#endif

#ifdef ZMQ_HAVE_OPENVMS
#include <ioctl.h>
#endif

zmq::tcp_listener_t::tcp_listener_t (io_thread_t *io_thread_,
                                     socket_base_t *socket_,
                                     const options_t &options_) :
    stream_listener_base_t (io_thread_, socket_, options_)
{
}

void zmq::tcp_listener_t::in_event ()
{
    fd_t fd = accept ();

    //  If connection was reset by the peer in the meantime, just ignore it.
    //  TODO: Handle specific errors like ENFILE/EMFILE etc.
    if (fd == retired_fd) {
        _socket->event_accept_failed (
          make_unconnected_bind_endpoint_pair (_endpoint), zmq_errno ());
        return;
    }

    int rc = tune_tcp_socket (fd);
    rc = rc
         | tune_tcp_keepalives (
             fd, options.tcp_keepalive, options.tcp_keepalive_cnt,
             options.tcp_keepalive_idle, options.tcp_keepalive_intvl);
    rc = rc | tune_tcp_maxrt (fd, options.tcp_maxrt);
    if (rc != 0) {
        _socket->event_accept_failed (
          make_unconnected_bind_endpoint_pair (_endpoint), zmq_errno ());
        return;
    }

    //  Create the engine object for this connection.
    create_engine (fd);
}

std::string
zmq::tcp_listener_t::get_socket_name (zmq::fd_t fd_,
                                      socket_end_t socket_end_) const
{
    return zmq::get_socket_name<tcp_address_t> (fd_, socket_end_);
}

int zmq::tcp_listener_t::set_local_address (const char *addr_)
{
    //  Convert the textual address into address structure.
    int rc = _address.resolve (addr_, true, options.ipv6);
    if (rc != 0)
        return -1;

    _address.to_string (_endpoint);

    if (options.use_fd != -1) {
        _s = options.use_fd;
        _socket->event_listening (
          make_unconnected_bind_endpoint_pair (_endpoint), _s);
        return 0;
    }

    //  Create a listening socket.
    _s = open_socket (_address.family (), SOCK_STREAM, IPPROTO_TCP);

    //  IPv6 address family not supported, try automatic downgrade to IPv4.
    if (_s == zmq::retired_fd && _address.family () == AF_INET6
        && errno == EAFNOSUPPORT && options.ipv6) {
        rc = _address.resolve (addr_, true, false);
        if (rc != 0)
            return rc;
        _s = open_socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
    }

    if (_s == retired_fd) {
        return -1;
    }
    make_socket_noninheritable (_s);

    //  On some systems, IPv4 mapping in IPv6 sockets is disabled by default.
    //  Switch it on in such cases.
    if (_address.family () == AF_INET6)
        enable_ipv4_mapping (_s);

    // Set the IP Type-Of-Service for the underlying socket
    if (options.tos != 0)
        set_ip_type_of_service (_s, options.tos);

    // Set the socket to loopback fastpath if configured.
    if (options.loopback_fastpath)
        tcp_tune_loopback_fast_path (_s);

    // Bind the socket to a device if applicable
    if (!options.bound_device.empty ())
        bind_to_device (_s, options.bound_device);

    //  Set the socket buffer limits for the underlying socket.
    if (options.sndbuf >= 0)
        set_tcp_send_buffer (_s, options.sndbuf);
    if (options.rcvbuf >= 0)
        set_tcp_receive_buffer (_s, options.rcvbuf);

    //  Allow reusing of the address.
    int flag = 1;
#ifdef ZMQ_HAVE_WINDOWS
    rc = setsockopt (_s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                     reinterpret_cast<const char *> (&flag), sizeof (int));
    wsa_assert (rc != SOCKET_ERROR);
#elif defined ZMQ_HAVE_VXWORKS
    rc =
      setsockopt (_s, SOL_SOCKET, SO_REUSEADDR, (char *) &flag, sizeof (int));
    errno_assert (rc == 0);
#else
    rc = setsockopt (_s, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof (int));
    errno_assert (rc == 0);
#endif

    //  Bind the socket to the network interface and port.
#if defined ZMQ_HAVE_VXWORKS
    rc = bind (_s, (sockaddr *) _address.addr (), _address.addrlen ());
#else
    rc = bind (_s, _address.addr (), _address.addrlen ());
#endif
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
    rc = listen (_s, options.backlog);
#ifdef ZMQ_HAVE_WINDOWS
    if (rc == SOCKET_ERROR) {
        errno = wsa_error_to_errno (WSAGetLastError ());
        goto error;
    }
#else
    if (rc != 0)
        goto error;
#endif

    _socket->event_listening (make_unconnected_bind_endpoint_pair (_endpoint),
                              _s);
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
    zmq_assert (_s != retired_fd);

    struct sockaddr_storage ss;
    memset (&ss, 0, sizeof (ss));
#if defined ZMQ_HAVE_HPUX || defined ZMQ_HAVE_VXWORKS
    int ss_len = sizeof (ss);
#else
    socklen_t ss_len = sizeof (ss);
#endif
#if defined ZMQ_HAVE_SOCK_CLOEXEC && defined HAVE_ACCEPT4
    fd_t sock = ::accept4 (_s, reinterpret_cast<struct sockaddr *> (&ss),
                           &ss_len, SOCK_CLOEXEC);
#else
    fd_t sock =
      ::accept (_s, reinterpret_cast<struct sockaddr *> (&ss), &ss_len);
#endif

    if (sock == retired_fd) {
#if defined ZMQ_HAVE_WINDOWS
        const int last_error = WSAGetLastError ();
        wsa_assert (last_error == WSAEWOULDBLOCK || last_error == WSAECONNRESET
                    || last_error == WSAEMFILE || last_error == WSAENOBUFS);
#elif defined ZMQ_HAVE_ANDROID
        errno_assert (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR
                      || errno == ECONNABORTED || errno == EPROTO
                      || errno == ENOBUFS || errno == ENOMEM || errno == EMFILE
                      || errno == ENFILE || errno == EINVAL);
#else
        errno_assert (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR
                      || errno == ECONNABORTED || errno == EPROTO
                      || errno == ENOBUFS || errno == ENOMEM || errno == EMFILE
                      || errno == ENFILE);
#endif
        return retired_fd;
    }

    make_socket_noninheritable (sock);

    if (!options.tcp_accept_filters.empty ()) {
        bool matched = false;
        for (options_t::tcp_accept_filters_t::size_type i = 0;
             i != options.tcp_accept_filters.size (); ++i) {
            if (options.tcp_accept_filters[i].match_address (
                  reinterpret_cast<struct sockaddr *> (&ss), ss_len)) {
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

    if (zmq::set_nosigpipe (sock)) {
#ifdef ZMQ_HAVE_WINDOWS
        int rc = closesocket (sock);
        wsa_assert (rc != SOCKET_ERROR);
#else
        int rc = ::close (sock);
        errno_assert (rc == 0);
#endif
        return retired_fd;
    }

    // Set the IP Type-Of-Service priority for this client socket
    if (options.tos != 0)
        set_ip_type_of_service (sock, options.tos);

    return sock;
}
