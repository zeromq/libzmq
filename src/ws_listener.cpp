/*
    Copyright (c) 2007-2019 Contributors as noted in the AUTHORS file

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

#include "ws_listener.hpp"
#include "io_thread.hpp"
#include "config.hpp"
#include "err.hpp"
#include "ip.hpp"
#include "tcp.hpp"
#include "socket_base.hpp"
#include "address.hpp"
#include "ws_engine.hpp"
#include "session_base.hpp"

#ifdef ZMQ_HAVE_WSS
#include "wss_engine.hpp"
#include "wss_address.hpp"
#endif

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

zmq::ws_listener_t::ws_listener_t (io_thread_t *io_thread_,
                                   socket_base_t *socket_,
                                   const options_t &options_,
                                   bool wss_) :
    stream_listener_base_t (io_thread_, socket_, options_),
    _wss (wss_)
{
#ifdef ZMQ_HAVE_WSS
    if (_wss) {
        int rc = gnutls_certificate_allocate_credentials (&_tls_cred);
        zmq_assert (rc == GNUTLS_E_SUCCESS);

        gnutls_datum_t cert = {(unsigned char *) options_.wss_cert_pem.c_str (),
                               (unsigned int) options_.wss_cert_pem.length ()};
        gnutls_datum_t key = {(unsigned char *) options_.wss_key_pem.c_str (),
                              (unsigned int) options_.wss_key_pem.length ()};
        rc = gnutls_certificate_set_x509_key_mem (_tls_cred, &cert, &key,
                                                  GNUTLS_X509_FMT_PEM);
        zmq_assert (rc == GNUTLS_E_SUCCESS);
    }
#endif
}

zmq::ws_listener_t::~ws_listener_t ()
{
#ifdef ZMQ_HAVE_WSS
    if (_wss)
        gnutls_certificate_free_credentials (_tls_cred);
#endif
}

void zmq::ws_listener_t::in_event ()
{
    const fd_t fd = accept ();

    //  If connection was reset by the peer in the meantime, just ignore it.
    //  TODO: Handle specific errors like ENFILE/EMFILE etc.
    if (fd == retired_fd) {
        _socket->event_accept_failed (
          make_unconnected_bind_endpoint_pair (_endpoint), zmq_errno ());
        return;
    }

    int rc = tune_tcp_socket (fd);
    rc = rc | tune_tcp_maxrt (fd, options.tcp_maxrt);
    if (rc != 0) {
        _socket->event_accept_failed (
          make_unconnected_bind_endpoint_pair (_endpoint), zmq_errno ());
        return;
    }

    //  Create the engine object for this connection.
    create_engine (fd);
}

std::string zmq::ws_listener_t::get_socket_name (zmq::fd_t fd_,
                                                 socket_end_t socket_end_) const
{
    std::string socket_name;

#ifdef ZMQ_HAVE_WSS
    if (_wss)
        socket_name = zmq::get_socket_name<wss_address_t> (fd_, socket_end_);
    else
#endif
        socket_name = zmq::get_socket_name<ws_address_t> (fd_, socket_end_);

    return socket_name + _address.path ();
}

int zmq::ws_listener_t::create_socket (const char *addr_)
{
    tcp_address_t address;
    _s = tcp_open_socket (addr_, options, true, true, &address);
    if (_s == retired_fd) {
        return -1;
    }

    //  TODO why is this only done for the listener?
    make_socket_noninheritable (_s);

    //  Allow reusing of the address.
    int flag = 1;
    int rc;
#ifdef ZMQ_HAVE_WINDOWS
    //  TODO this was changed for Windows from SO_REUSEADDRE to
    //  SE_EXCLUSIVEADDRUSE by 0ab65324195ad70205514d465b03d851a6de051c,
    //  so the comment above is no longer correct; also, now the settings are
    //  different between listener and connecter with a src address.
    //  is this intentional?
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
    rc = bind (_s, address.addr (), address.addrlen ());
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

    return 0;

error:
    const int err = errno;
    close ();
    errno = err;
    return -1;
}

int zmq::ws_listener_t::set_local_address (const char *addr_)
{
    if (options.use_fd != -1) {
        //  in this case, the addr_ passed is not used and ignored, since the
        //  socket was already created by the application
        _s = options.use_fd;
    } else {
        const int rc = _address.resolve (addr_, true, options.ipv6);
        if (rc != 0)
            return -1;

        //  remove the path, otherwise resolving the port will fail with wildcard
        const char *delim = strrchr (addr_, '/');
        std::string host_address;
        if (delim) {
            host_address = std::string (addr_, delim - addr_);
        } else {
            host_address = addr_;
        }

        if (create_socket (host_address.c_str ()) == -1)
            return -1;
    }

    _endpoint = get_socket_name (_s, socket_end_local);

    _socket->event_listening (make_unconnected_bind_endpoint_pair (_endpoint),
                              _s);
    return 0;
}

zmq::fd_t zmq::ws_listener_t::accept ()
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
    const fd_t sock =
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

    if (zmq::set_nosigpipe (sock)) {
#ifdef ZMQ_HAVE_WINDOWS
        const int rc = closesocket (sock);
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

void zmq::ws_listener_t::create_engine (fd_t fd_)
{
    const endpoint_uri_pair_t endpoint_pair (
      get_socket_name (fd_, socket_end_local),
      get_socket_name (fd_, socket_end_remote), endpoint_type_bind);

    i_engine *engine = NULL;
    if (_wss)
#ifdef ZMQ_HAVE_WSS
        engine = new (std::nothrow)
          wss_engine_t (fd_, options, endpoint_pair, _address, false, _tls_cred,
                        std::string ());
#else
        zmq_assert (false);
#endif
    else
        engine = new (std::nothrow)
          ws_engine_t (fd_, options, endpoint_pair, _address, false);

    alloc_assert (engine);

    //  Choose I/O thread to run connecter in. Given that we are already
    //  running in an I/O thread, there must be at least one available.
    io_thread_t *io_thread = choose_io_thread (options.affinity);
    zmq_assert (io_thread);

    //  Create and launch a session object.
    session_base_t *session =
      session_base_t::create (io_thread, false, _socket, options, NULL);
    errno_assert (session);
    session->inc_seqnum ();
    launch_child (session);
    send_attach (session, engine, false);

    _socket->event_accepted (endpoint_pair, fd_);
}
