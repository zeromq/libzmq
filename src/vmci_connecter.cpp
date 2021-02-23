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

#include "vmci_connecter.hpp"

#if defined ZMQ_HAVE_VMCI

#include <new>

#include "io_thread.hpp"
#include "platform.hpp"
#include "random.hpp"
#include "err.hpp"
#include "ip.hpp"
#include "address.hpp"
#include "vmci_address.hpp"
#include "vmci.hpp"
#include "session_base.hpp"

zmq::vmci_connecter_t::vmci_connecter_t (class io_thread_t *io_thread_,
                                         class session_base_t *session_,
                                         const options_t &options_,
                                         address_t *addr_,
                                         bool delayed_start_) :
    stream_connecter_base_t (
      io_thread_, session_, options_, addr_, delayed_start_),
    _connect_timer_started (false)
{
    zmq_assert (_addr->protocol == protocol_name::vmci);
}

zmq::vmci_connecter_t::~vmci_connecter_t ()
{
    zmq_assert (!_connect_timer_started);
}

void zmq::vmci_connecter_t::process_term (int linger_)
{
    if (_connect_timer_started) {
        cancel_timer (connect_timer_id);
        _connect_timer_started = false;
    }

    stream_connecter_base_t::process_term (linger_);
}

void zmq::vmci_connecter_t::in_event ()
{
    //  We are not polling for incoming data, so we are actually called
    //  because of error here. However, we can get error on out event as well
    //  on some platforms, so we'll simply handle both events in the same way.
    out_event ();
}

void zmq::vmci_connecter_t::out_event ()
{
    if (_connect_timer_started) {
        cancel_timer (connect_timer_id);
        _connect_timer_started = false;
    }

    //  TODO this is still very similar to (t)ipc_connecter_t, maybe the
    //  differences can be factored out

    rm_handle ();

    const fd_t fd = connect ();

    if (fd == retired_fd
        && ((options.reconnect_stop & ZMQ_RECONNECT_STOP_CONN_REFUSED)
            && errno == ECONNREFUSED)) {
        send_conn_failed (_session);
        close ();
        terminate ();
        return;
    }

    //  Handle the error condition by attempt to reconnect.
    if (fd == retired_fd) {
        close ();
        add_reconnect_timer ();
        return;
    }

    tune_vmci_buffer_size (this->get_ctx (), fd, options.vmci_buffer_size,
                           options.vmci_buffer_min_size,
                           options.vmci_buffer_max_size);

    if (options.vmci_connect_timeout > 0) {
#if defined ZMQ_HAVE_WINDOWS
        tune_vmci_connect_timeout (this->get_ctx (), fd,
                                   options.vmci_connect_timeout);
#else
        struct timeval timeout = {0, options.vmci_connect_timeout * 1000};
        tune_vmci_connect_timeout (this->get_ctx (), fd, timeout);
#endif
    }

    create_engine (
      fd, zmq::vmci_connecter_t::get_socket_name (fd, socket_end_local));
}

std::string
zmq::vmci_connecter_t::get_socket_name (zmq::fd_t fd_,
                                        socket_end_t socket_end_) const
{
    struct sockaddr_storage ss;
    const zmq_socklen_t sl = get_socket_address (fd_, socket_end_, &ss);
    if (sl == 0) {
        return std::string ();
    }

    const vmci_address_t addr (reinterpret_cast<struct sockaddr *> (&ss), sl,
                               this->get_ctx ());
    std::string address_string;
    addr.to_string (address_string);
    return address_string;
}

void zmq::vmci_connecter_t::timer_event (int id_)
{
    if (id_ == connect_timer_id) {
        _connect_timer_started = false;
        rm_handle ();
        close ();
        add_reconnect_timer ();
    } else
        stream_connecter_base_t::timer_event (id_);
}

void zmq::vmci_connecter_t::start_connecting ()
{
    //  Open the connecting socket.
    const int rc = open ();

    //  Connect may succeed in synchronous manner.
    if (rc == 0) {
        _handle = add_fd (_s);
        out_event ();
    }

    //  Connection establishment may be delayed. Poll for its completion.
    else if (rc == -1 && errno == EINPROGRESS) {
        _handle = add_fd (_s);
        set_pollout (_handle);
        _socket->event_connect_delayed (
          make_unconnected_connect_endpoint_pair (_endpoint), zmq_errno ());

        //  add userspace connect timeout
        add_connect_timer ();
    }

    //  Handle any other error condition by eventual reconnect.
    else {
        if (_s != retired_fd)
            close ();
        add_reconnect_timer ();
    }
}

void zmq::vmci_connecter_t::add_connect_timer ()
{
    if (options.connect_timeout > 0) {
        add_timer (options.connect_timeout, connect_timer_id);
        _connect_timer_started = true;
    }
}

int zmq::vmci_connecter_t::open ()
{
    zmq_assert (_s == retired_fd);

    //  Resolve the address
    if (_addr->resolved.vmci_addr != NULL) {
        LIBZMQ_DELETE (_addr->resolved.vmci_addr);
    }

    _addr->resolved.vmci_addr =
      new (std::nothrow) vmci_address_t (this->get_ctx ());
    alloc_assert (_addr->resolved.vmci_addr);
    _s = vmci_open_socket (_addr->address.c_str (), options,
                           _addr->resolved.vmci_addr);
    if (_s == retired_fd) {
        //  TODO we should emit some event in this case!

        LIBZMQ_DELETE (_addr->resolved.vmci_addr);
        return -1;
    }
    zmq_assert (_addr->resolved.vmci_addr != NULL);

    // Set the socket to non-blocking mode so that we get async connect().
    unblock_socket (_s);

    const vmci_address_t *const vmci_addr = _addr->resolved.vmci_addr;

    int rc;

    //  Connect to the remote peer.
#if defined ZMQ_HAVE_VXWORKS
    rc = ::connect (_s, (sockaddr *) vmci_addr->addr (), vmci_addr->addrlen ());
#else
    rc = ::connect (_s, vmci_addr->addr (), vmci_addr->addrlen ());
#endif
    //  Connect was successful immediately.
    if (rc == 0) {
        return 0;
    }

    //  Translate error codes indicating asynchronous connect has been
    //  launched to a uniform EINPROGRESS.
#ifdef ZMQ_HAVE_WINDOWS
    const int last_error = WSAGetLastError ();
    if (last_error == WSAEINPROGRESS || last_error == WSAEWOULDBLOCK)
        errno = EINPROGRESS;
    else
        errno = wsa_error_to_errno (last_error);
#else
    if (errno == EINTR)
        errno = EINPROGRESS;
#endif
    return -1;
}

zmq::fd_t zmq::vmci_connecter_t::connect ()
{
    //  Async connect has finished. Check whether an error occurred
    int err = 0;
#if defined ZMQ_HAVE_HPUX || defined ZMQ_HAVE_VXWORKS
    int len = sizeof err;
#else
    socklen_t len = sizeof err;
#endif

    const int rc = getsockopt (_s, SOL_SOCKET, SO_ERROR,
                               reinterpret_cast<char *> (&err), &len);

    //  Assert if the error was caused by 0MQ bug.
    //  Networking problems are OK. No need to assert.
#ifdef ZMQ_HAVE_WINDOWS
    zmq_assert (rc == 0);
    if (err != 0) {
        if (err == WSAEBADF || err == WSAENOPROTOOPT || err == WSAENOTSOCK
            || err == WSAENOBUFS) {
            wsa_assert_no (err);
        }
        errno = wsa_error_to_errno (err);
        return retired_fd;
    }
#else
    //  Following code should handle both Berkeley-derived socket
    //  implementations and Solaris.
    if (rc == -1)
        err = errno;
    if (err != 0) {
        errno = err;
#if !defined(TARGET_OS_IPHONE) || !TARGET_OS_IPHONE
        errno_assert (errno != EBADF && errno != ENOPROTOOPT
                      && errno != ENOTSOCK && errno != ENOBUFS);
#else
        errno_assert (errno != ENOPROTOOPT && errno != ENOTSOCK
                      && errno != ENOBUFS);
#endif
        return retired_fd;
    }
#endif

    //  Return the newly connected socket.
    const fd_t result = _s;
    _s = retired_fd;
    return result;
}

#endif
