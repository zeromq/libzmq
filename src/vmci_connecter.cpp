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

#include "stream_engine.hpp"
#include "io_thread.hpp"
#include "platform.hpp"
#include "random.hpp"
#include "err.hpp"
#include "ip.hpp"
#include "address.hpp"
#include "session_base.hpp"
#include "vmci_address.hpp"
#include "vmci.hpp"

zmq::vmci_connecter_t::vmci_connecter_t (class io_thread_t *io_thread_,
                                         class session_base_t *session_,
                                         const options_t &options_,
                                         const address_t *addr_,
                                         bool delayed_start_) :
    own_t (io_thread_, options_),
    io_object_t (io_thread_),
    addr (addr_),
    s (retired_fd),
    handle_valid (false),
    delayed_start (delayed_start_),
    timer_started (false),
    session (session_),
    current_reconnect_ivl (options.reconnect_ivl)
{
    zmq_assert (addr);
    zmq_assert (addr->protocol == "vmci");
    addr->to_string (endpoint);
    socket = session->get_socket ();
}

zmq::vmci_connecter_t::~vmci_connecter_t ()
{
    zmq_assert (!timer_started);
    zmq_assert (!handle_valid);
    zmq_assert (s == retired_fd);
}

void zmq::vmci_connecter_t::process_plug ()
{
    if (delayed_start)
        add_reconnect_timer ();
    else
        start_connecting ();
}

void zmq::vmci_connecter_t::process_term (int linger_)
{
    if (timer_started) {
        cancel_timer (reconnect_timer_id);
        timer_started = false;
    }

    if (handle_valid) {
        rm_fd (handle);
        handle_valid = false;
    }

    if (s != retired_fd)
        close ();

    own_t::process_term (linger_);
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
    fd_t fd = connect ();
    rm_fd (handle);
    handle_valid = false;

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

    //  Create the engine object for this connection.
    stream_engine_t *engine = new (std::nothrow) stream_engine_t (
      fd, options, make_unconnected_bind_endpoint_pair (endpoint));
    alloc_assert (engine);

    //  Attach the engine to the corresponding session object.
    send_attach (session, engine);

    //  Shut the connecter down.
    terminate ();

    socket->event_connected (make_unconnected_bind_endpoint_pair (endpoint),
                             fd);
}

void zmq::vmci_connecter_t::timer_event (int id_)
{
    zmq_assert (id_ == reconnect_timer_id);
    timer_started = false;
    start_connecting ();
}

void zmq::vmci_connecter_t::start_connecting ()
{
    //  Open the connecting socket.
    int rc = open ();

    //  Connect may succeed in synchronous manner.
    if (rc == 0) {
        handle = add_fd (s);
        handle_valid = true;
        out_event ();
    }

    //  Handle any other error condition by eventual reconnect.
    else {
        if (s != retired_fd)
            close ();
        add_reconnect_timer ();
    }
}

void zmq::vmci_connecter_t::add_reconnect_timer ()
{
    if (options.reconnect_ivl != -1) {
        int rc_ivl = get_new_reconnect_ivl ();
        add_timer (rc_ivl, reconnect_timer_id);
        socket->event_connect_retried (
          make_unconnected_bind_endpoint_pair (endpoint), rc_ivl);
        timer_started = true;
    }
}

int zmq::vmci_connecter_t::get_new_reconnect_ivl ()
{
    //  The new interval is the current interval + random value.
    int this_interval =
      current_reconnect_ivl + (generate_random () % options.reconnect_ivl);

    //  Only change the current reconnect interval  if the maximum reconnect
    //  interval was set and if it's larger than the reconnect interval.
    if (options.reconnect_ivl_max > 0
        && options.reconnect_ivl_max > options.reconnect_ivl) {
        //  Calculate the next interval
        current_reconnect_ivl = current_reconnect_ivl * 2;
        if (current_reconnect_ivl >= options.reconnect_ivl_max) {
            current_reconnect_ivl = options.reconnect_ivl_max;
        }
    }
    return this_interval;
}

int zmq::vmci_connecter_t::open ()
{
    zmq_assert (s == retired_fd);

    int family = this->get_ctx ()->get_vmci_socket_family ();
    if (family == -1)
        return -1;

    //  Create the socket.
    s = open_socket (family, SOCK_STREAM, 0);
#ifdef ZMQ_HAVE_WINDOWS
    if (s == INVALID_SOCKET) {
        errno = wsa_error_to_errno (WSAGetLastError ());
        return -1;
    }
#else
    if (s == -1)
        return -1;
#endif

    //  Connect to the remote peer.
    int rc = ::connect (s, addr->resolved.vmci_addr->addr (),
                        addr->resolved.vmci_addr->addrlen ());

    //  Connect was successful immediately.
    if (rc == 0)
        return 0;

    //  Forward the error.
    return -1;
}

void zmq::vmci_connecter_t::close ()
{
    zmq_assert (s != retired_fd);
#ifdef ZMQ_HAVE_WINDOWS
    const int rc = closesocket (s);
    wsa_assert (rc != SOCKET_ERROR);
#else
    const int rc = ::close (s);
    errno_assert (rc == 0);
#endif
    socket->event_closed (make_unconnected_bind_endpoint_pair (endpoint), s);
    s = retired_fd;
}

zmq::fd_t zmq::vmci_connecter_t::connect ()
{
    //  Following code should handle both Berkeley-derived socket
    //  implementations and Solaris.
    int err = 0;
#if defined ZMQ_HAVE_HPUX
    int len = sizeof (err);
#else
    socklen_t len = sizeof (err);
#endif
    int rc = getsockopt (s, SOL_SOCKET, SO_ERROR, (char *) &err, &len);

    //  Assert if the error was caused by 0MQ bug.
    //  Networking problems are OK. No need to assert.
#ifdef ZMQ_HAVE_WINDOWS
    zmq_assert (rc == 0);
    if (err != 0) {
        if (err != WSAECONNREFUSED && err != WSAETIMEDOUT
            && err != WSAECONNABORTED && err != WSAEHOSTUNREACH
            && err != WSAENETUNREACH && err != WSAENETDOWN && err != WSAEACCES
            && err != WSAEINVAL && err != WSAEADDRINUSE
            && err != WSAECONNRESET) {
            wsa_assert_no (err);
        }
        return retired_fd;
    }
#else
    //  Following code should handle both Berkeley-derived socket
    //  implementations and Solaris.
    if (rc == -1)
        err = errno;
    if (err != 0) {
        errno = err;
        errno_assert (errno == ECONNREFUSED || errno == ECONNRESET
                      || errno == ETIMEDOUT || errno == EHOSTUNREACH
                      || errno == ENETUNREACH || errno == ENETDOWN
                      || errno == EINVAL);
        return retired_fd;
    }
#endif

    fd_t result = s;
    s = retired_fd;
    return result;
}

#endif
