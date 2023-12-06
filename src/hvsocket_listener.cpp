/* SPDX-License-Identifier: MPL-2.0 */

#include "precompiled.hpp"

#include "hvsocket_listener.hpp"

#if defined ZMQ_HAVE_HVSOCKET

#include <new>

#include "hvsocket_address.hpp"
#include "io_thread.hpp"
#include "session_base.hpp"
#include "config.hpp"
#include "err.hpp"
#include "ip.hpp"
#include "socket_base.hpp"
#include "hvsocket.hpp"

#if defined ZMQ_HAVE_WINDOWS
#include "windows.hpp"
#else
#include <unistd.h>
#include <fcntl.h>
#endif

zmq::hvsocket_listener_t::hvsocket_listener_t (io_thread_t *io_thread_,
                                       socket_base_t *socket_,
                                       const options_t &options_) :
    stream_listener_base_t (io_thread_, socket_, options_)
{
}

void zmq::hvsocket_listener_t::in_event ()
{
    fd_t fd = accept ();

    //  If connection was reset by the peer in the meantime, just ignore it.
    if (fd == retired_fd) {
        _socket->event_accept_failed (
          make_unconnected_bind_endpoint_pair (_endpoint), zmq_errno ());
        return;
    }

    //  Create the engine object for this connection.
    create_engine (fd);
}

std::string
zmq::hvsocket_listener_t::get_socket_name (zmq::fd_t fd_,
                                       socket_end_t socket_end_) const
{
    struct sockaddr_storage ss;
    const zmq_socklen_t sl = get_socket_address (fd_, socket_end_, &ss);
    if (sl == 0) {
        return std::string ();
    }

    const hvsocket_address_t addr (reinterpret_cast<struct sockaddr *> (&ss), sl,
                               this->get_ctx ());
    std::string address_string;
    addr.to_string (address_string);
    return address_string;
}

int zmq::hvsocket_listener_t::set_local_address (const char *addr_)
{
    //
    //  Create addr on stack for auto-cleanup
    //

    std::string addr (addr_);

    //
    //  Initialise the address structure.
    //

    hvsocket_address_t address (this->get_ctx ());
    int rc = address.resolve (addr.c_str ());

    if (rc != 0) {
        return -1;
    }
                          
    //
    //  Create a listening socket.
    //

    _s = open_socket (this->get_ctx ()->get_hvsocket_socket_family (),
                      SOCK_STREAM, HV_PROTOCOL_RAW);

#ifdef ZMQ_HAVE_WINDOWS
    if (_s == INVALID_SOCKET) {
        errno = wsa_error_to_errno (WSAGetLastError ());
        return -1;
    }

    //
    // Ensure the socket is not inherited by child processes.
    //

    BOOL brc = SetHandleInformation ((HANDLE) _s, HANDLE_FLAG_INHERIT, 0);
    win_assert (brc);
#else
    if (_s == -1) {
        return -1;
    }
#endif

    //
    // Best effort to set socket options.
    //

    const int non_zero_value = 1;

    if (options.hvsocket_container_passthru) {
        rc =
          setsockopt (_s, HV_PROTOCOL_RAW, HVSOCKET_CONTAINER_PASSTHRU,
                      (const char *) &non_zero_value, sizeof (non_zero_value));
#ifndef NDEBUG
        zmq_assert (rc == 0);
#else
        LIBZMQ_UNUSED (rc);
#endif
    }

    if (options.hvsocket_connected_suspend) {
        rc =
          setsockopt (_s, HV_PROTOCOL_RAW, HVSOCKET_CONNECTED_SUSPEND,
                      (const char *) &non_zero_value, sizeof (non_zero_value));
#ifndef NDEBUG
        zmq_assert (rc == 0);
#else
        LIBZMQ_UNUSED (rc);
#endif
    }

    if (options.hvsocket_high_vtl) {
        rc =
          setsockopt (_s, HV_PROTOCOL_RAW, HVSOCKET_HIGH_VTL,
                      (const char *) &non_zero_value, sizeof (non_zero_value));
#ifndef NDEBUG
        zmq_assert (rc == 0);
#else
        LIBZMQ_UNUSED (rc);
#endif
    }

    if (options.connect_timeout > 0) {
        rc = setsockopt (_s, HV_PROTOCOL_RAW, HVSOCKET_CONNECT_TIMEOUT,
                         (const char *) &options.connect_timeout,
                         sizeof (options.connect_timeout));
#ifndef NDEBUG
        zmq_assert (rc == 0);
#endif
    }

    address.to_string (_endpoint);

    //
    // Bind the socket.
    //

    rc = bind (_s, address.addr (), address.addrlen ());
#ifdef ZMQ_HAVE_WINDOWS
    if (rc == SOCKET_ERROR) {
        errno = wsa_error_to_errno (WSAGetLastError ());
        goto error;
    }
#else
    if (rc != 0)
        goto error;
#endif

    //
    // Listen for incoming connections.
    //

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

zmq::fd_t zmq::hvsocket_listener_t::accept ()
{
    //
    //  Accept one connection and deal with different failure modes.
    //  The situation where connection cannot be accepted due to insufficient
    //  resources is considered valid and treated by ignoring the connection.
    //

    zmq_assert (_s != retired_fd);
    fd_t sock = ::accept (_s, NULL, NULL);

#ifdef ZMQ_HAVE_WINDOWS
    if (sock == INVALID_SOCKET) {
        wsa_assert (WSAGetLastError () == WSAEWOULDBLOCK
                    || WSAGetLastError () == WSAECONNRESET
                    || WSAGetLastError () == WSAEMFILE
                    || WSAGetLastError () == WSAENOBUFS);
        return retired_fd;
    }

    BOOL brc = SetHandleInformation ((HANDLE) sock, HANDLE_FLAG_INHERIT, 0);
    win_assert (brc);
#else
    if (sock == -1) {
        errno_assert (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR
                      || errno == ECONNABORTED || errno == EPROTO
                      || errno == ENOBUFS || errno == ENOMEM || errno == EMFILE
                      || errno == ENFILE);
        return retired_fd;
    }
#endif

    //
    //  Race condition can cause socket not to be closed (if fork happens
    //  between accept and this point).
    //

#ifdef FD_CLOEXEC
    int rc = fcntl (sock, F_SETFD, FD_CLOEXEC);
    errno_assert (rc != -1);
#endif

    return sock;
}

#endif
