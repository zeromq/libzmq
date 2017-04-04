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

#include "vmci_listener.hpp"

#if defined ZMQ_HAVE_VMCI

#include <new>

#include "stream_engine.hpp"
#include "vmci_address.hpp"
#include "io_thread.hpp"
#include "session_base.hpp"
#include "config.hpp"
#include "err.hpp"
#include "ip.hpp"
#include "socket_base.hpp"
#include "vmci.hpp"

#if defined ZMQ_HAVE_WINDOWS
#include "windows.hpp"
#else
#include <unistd.h>
#include <fcntl.h>
#endif

zmq::vmci_listener_t::vmci_listener_t (io_thread_t *io_thread_,
      socket_base_t *socket_, const options_t &options_) :
    own_t (io_thread_, options_),
    io_object_t (io_thread_),
    s (retired_fd),
    socket (socket_)
{
}

zmq::vmci_listener_t::~vmci_listener_t ()
{
    zmq_assert (s == retired_fd);
}

void zmq::vmci_listener_t::process_plug ()
{
    //  Start polling for incoming connections.
    handle = add_fd (s);
    set_pollin (handle);
}

void zmq::vmci_listener_t::process_term (int linger_)
{
    rm_fd (handle);
    close ();
    own_t::process_term (linger_);
}

void zmq::vmci_listener_t::in_event ()
{
    fd_t fd = accept ();

    //  If connection was reset by the peer in the meantime, just ignore it.
    if (fd == retired_fd) {
        socket->event_accept_failed (endpoint, zmq_errno());
        return;
    }

    tune_vmci_buffer_size (this->get_ctx (), fd, options.vmci_buffer_size, options.vmci_buffer_min_size, options.vmci_buffer_max_size);

    if (options.vmci_connect_timeout > 0)
    {
#if defined ZMQ_HAVE_WINDOWS
        tune_vmci_connect_timeout (this->get_ctx (), fd, options.vmci_connect_timeout);
#else
        struct timeval timeout = {0, options.vmci_connect_timeout * 1000};
        tune_vmci_connect_timeout (this->get_ctx (), fd, timeout);
#endif
    }

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

int zmq::vmci_listener_t::get_address (std::string &addr_)
{
    struct sockaddr_storage ss;
#ifdef ZMQ_HAVE_HPUX
    int sl = sizeof (ss);
#else
    socklen_t sl = sizeof (ss);
#endif
    int rc = getsockname (s, (sockaddr *) &ss, &sl);
    if (rc != 0) {
        addr_.clear ();
        return rc;
    }

    vmci_address_t addr ((struct sockaddr *) &ss, sl, this->get_ctx ());
    return addr.to_string (addr_);
}

int zmq::vmci_listener_t::set_address (const char *addr_)
{
    //  Create addr on stack for auto-cleanup
    std::string addr (addr_);

    //  Initialise the address structure.
    vmci_address_t address(this->get_ctx ());
    int rc = address.resolve (addr.c_str());
    if (rc != 0)
        return -1;

    //  Create a listening socket.
    s = open_socket (this->get_ctx ()->get_vmci_socket_family (), SOCK_STREAM, 0);
#ifdef ZMQ_HAVE_WINDOWS
    if (s == INVALID_SOCKET) {
        errno = wsa_error_to_errno(WSAGetLastError());
        return -1;
    }
#if !defined _WIN32_WCE
    //  On Windows, preventing sockets to be inherited by child processes.
    BOOL brc = SetHandleInformation((HANDLE)s, HANDLE_FLAG_INHERIT, 0);
    win_assert(brc);
#endif
#else
    if (s == -1)
        return -1;
#endif

    address.to_string (endpoint);

    //  Bind the socket.
    rc = bind (s, address.addr (), address.addrlen ());
#ifdef ZMQ_HAVE_WINDOWS
    if (rc == SOCKET_ERROR) {
        errno = wsa_error_to_errno(WSAGetLastError());
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
        errno = wsa_error_to_errno(WSAGetLastError());
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

void zmq::vmci_listener_t::close ()
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

zmq::fd_t zmq::vmci_listener_t::accept ()
{
    //  Accept one connection and deal with different failure modes.
    //  The situation where connection cannot be accepted due to insufficient
    //  resources is considered valid and treated by ignoring the connection.
    zmq_assert (s != retired_fd);
    fd_t sock = ::accept (s, NULL, NULL);

#ifdef ZMQ_HAVE_WINDOWS
    if (sock == INVALID_SOCKET) {
        wsa_assert(WSAGetLastError() == WSAEWOULDBLOCK ||
            WSAGetLastError() == WSAECONNRESET ||
            WSAGetLastError() == WSAEMFILE ||
            WSAGetLastError() == WSAENOBUFS);
        return retired_fd;
    }
#if !defined _WIN32_WCE
    //  On Windows, preventing sockets to be inherited by child processes.
    BOOL brc = SetHandleInformation((HANDLE)sock, HANDLE_FLAG_INHERIT, 0);
    win_assert(brc);
#endif
#else
    if (sock == -1) {
        errno_assert(errno == EAGAIN || errno == EWOULDBLOCK ||
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

    return sock;
}

#endif
