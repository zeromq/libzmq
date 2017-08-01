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

#include "macros.hpp"
#include "tcp_connecter.hpp"
#include "stream_engine.hpp"
#include "io_thread.hpp"
#include "random.hpp"
#include "err.hpp"
#include "ip.hpp"
#include "tcp.hpp"
#include "address.hpp"
#include "tcp_address.hpp"
#include "session_base.hpp"

#if !defined ZMQ_HAVE_WINDOWS
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#ifdef ZMQ_HAVE_OPENVMS
#include <ioctl.h>
#endif
#endif

zmq::tcp_connecter_t::tcp_connecter_t (class io_thread_t *io_thread_,
      class session_base_t *session_, const options_t &options_,
      address_t *addr_, bool delayed_start_) :
    own_t (io_thread_, options_),
    io_object_t (io_thread_),
    addr (addr_),
    s (retired_fd),
    handle((handle_t)NULL),
    handle_valid (false),
    delayed_start (delayed_start_),
    connect_timer_started (false),
    reconnect_timer_started (false),
    session (session_),
    current_reconnect_ivl (options.reconnect_ivl)
{
    zmq_assert (addr);
    zmq_assert (addr->protocol == "tcp");
    addr->to_string (endpoint);
    socket = session->get_socket ();
}

zmq::tcp_connecter_t::~tcp_connecter_t ()
{
    zmq_assert (!connect_timer_started);
    zmq_assert (!reconnect_timer_started);
    zmq_assert (!handle_valid);
    zmq_assert (s == retired_fd);
}

void zmq::tcp_connecter_t::process_plug ()
{
    if (delayed_start)
        add_reconnect_timer ();
    else
        start_connecting ();
}

void zmq::tcp_connecter_t::process_term (int linger_)
{
    if (connect_timer_started) {
        cancel_timer (connect_timer_id);
        connect_timer_started = false;
    }

    if (reconnect_timer_started) {
        cancel_timer (reconnect_timer_id);
        reconnect_timer_started = false;
    }

    if (handle_valid) {
        rm_fd (handle);
        handle_valid = false;
    }

    if (s != retired_fd)
        close ();

    own_t::process_term (linger_);
}

void zmq::tcp_connecter_t::in_event ()
{
    //  We are not polling for incoming data, so we are actually called
    //  because of error here. However, we can get error on out event as well
    //  on some platforms, so we'll simply handle both events in the same way.
    out_event ();
}

void zmq::tcp_connecter_t::out_event ()
{
    if (connect_timer_started) {
        cancel_timer (connect_timer_id);
        connect_timer_started = false;
    }

    rm_fd (handle);
    handle_valid = false;

    const fd_t fd = connect ();

    //  Handle the error condition by attempt to reconnect.
    if (fd == retired_fd) {
        close ();
        add_reconnect_timer ();
        return;
    }

    int rc = tune_tcp_socket (fd);
    rc = rc | tune_tcp_keepalives (fd, options.tcp_keepalive, options.tcp_keepalive_cnt,
        options.tcp_keepalive_idle, options.tcp_keepalive_intvl);
    rc = rc | tune_tcp_maxrt (fd, options.tcp_maxrt);
    if (rc != 0) {
        close ();
        add_reconnect_timer ();
        return;
    }

    //  Create the engine object for this connection.
    stream_engine_t *engine = new (std::nothrow)
        stream_engine_t (fd, options, endpoint);
    alloc_assert (engine);

    //  Attach the engine to the corresponding session object.
    send_attach (session, engine);

    //  Shut the connecter down.
    terminate ();

    socket->event_connected (endpoint, (int) fd);
}

void zmq::tcp_connecter_t::timer_event (int id_)
{
    zmq_assert (id_ == reconnect_timer_id || id_ == connect_timer_id);
    if (id_ == connect_timer_id) {
        connect_timer_started = false;

        rm_fd (handle);
        handle_valid = false;

        close ();
        add_reconnect_timer ();
    }
    else if (id_ == reconnect_timer_id) {
        reconnect_timer_started = false;
        start_connecting ();
    }
}

void zmq::tcp_connecter_t::start_connecting ()
{
    //  Open the connecting socket.
    const int rc = open ();

    //  Connect may succeed in synchronous manner.
    if (rc == 0) {
        handle = add_fd (s);
        handle_valid = true;
        out_event ();
    }

    //  Connection establishment may be delayed. Poll for its completion.
    else
    if (rc == -1 && errno == EINPROGRESS) {
        handle = add_fd (s);
        handle_valid = true;
        set_pollout (handle);
        socket->event_connect_delayed (endpoint, zmq_errno());

        //  add userspace connect timeout
        add_connect_timer ();
    }

    //  Handle any other error condition by eventual reconnect.
    else {
        if (s != retired_fd)
            close ();
        add_reconnect_timer ();
    }
}

void zmq::tcp_connecter_t::add_connect_timer ()
{
    if (options.connect_timeout > 0) {
        add_timer (options.connect_timeout, connect_timer_id);
        connect_timer_started = true;
    }
}

void zmq::tcp_connecter_t::add_reconnect_timer ()
{
    const int interval = get_new_reconnect_ivl ();
    add_timer (interval, reconnect_timer_id);
    socket->event_connect_retried (endpoint, interval);
    reconnect_timer_started = true;
}

int zmq::tcp_connecter_t::get_new_reconnect_ivl ()
{
    //  The new interval is the current interval + random value.
    const int interval = current_reconnect_ivl +
        generate_random () % options.reconnect_ivl;

    //  Only change the current reconnect interval  if the maximum reconnect
    //  interval was set and if it's larger than the reconnect interval.
    if (options.reconnect_ivl_max > 0 &&
        options.reconnect_ivl_max > options.reconnect_ivl)
        //  Calculate the next interval
        current_reconnect_ivl =
            std::min (current_reconnect_ivl * 2, options.reconnect_ivl_max);
    return interval;
}

int zmq::tcp_connecter_t::open ()
{
    zmq_assert (s == retired_fd);

    //  Resolve the address
    if (addr->resolved.tcp_addr != NULL) {
        LIBZMQ_DELETE(addr->resolved.tcp_addr);
    }

    addr->resolved.tcp_addr = new (std::nothrow) tcp_address_t ();
    alloc_assert (addr->resolved.tcp_addr);
    int rc = addr->resolved.tcp_addr->resolve (
        addr->address.c_str (), false, options.ipv6);
    if (rc != 0) {
        LIBZMQ_DELETE(addr->resolved.tcp_addr);
        return -1;
    }
    zmq_assert (addr->resolved.tcp_addr != NULL);
    tcp_address_t * const tcp_addr = addr->resolved.tcp_addr;

    //  Create the socket.
    s = open_socket (tcp_addr->family (), SOCK_STREAM, IPPROTO_TCP);

    //  IPv6 address family not supported, try automatic downgrade to IPv4.
    if (s == zmq::retired_fd && tcp_addr->family () == AF_INET6
    && errno == EAFNOSUPPORT
    && options.ipv6) {
        rc = addr->resolved.tcp_addr->resolve (
            addr->address.c_str (), false, false);
        if (rc != 0) {
            LIBZMQ_DELETE(addr->resolved.tcp_addr);
            return -1;
        }
        s = open_socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
    }

#ifdef ZMQ_HAVE_WINDOWS
    if (s == INVALID_SOCKET) {
        errno = wsa_error_to_errno (WSAGetLastError ());
        return -1;
    }
#else
    if (s == -1)
        return -1;
#endif

    //  On some systems, IPv4 mapping in IPv6 sockets is disabled by default.
    //  Switch it on in such cases.
    if (tcp_addr->family () == AF_INET6)
        enable_ipv4_mapping (s);

    // Set the IP Type-Of-Service priority for this socket
    if (options.tos != 0)
        set_ip_type_of_service (s, options.tos);

    // Bind the socket to a device if applicable
    if (!options.bound_device.empty ())
        bind_to_device (s, options.bound_device);

    // Set the socket to non-blocking mode so that we get async connect().
    unblock_socket (s);

    //  Set the socket buffer limits for the underlying socket.
    if (options.sndbuf >= 0)
        set_tcp_send_buffer (s, options.sndbuf);
    if (options.rcvbuf >= 0)
        set_tcp_receive_buffer (s, options.rcvbuf);

    // Set the IP Type-Of-Service for the underlying socket
    if (options.tos != 0)
        set_ip_type_of_service (s, options.tos);

    // Set a source address for conversations
    if (tcp_addr->has_src_addr ()) {
        //  Allow reusing of the address, to connect to different servers
        //  using the same source port on the client.
        int flag = 1;
#ifdef ZMQ_HAVE_WINDOWS
        rc = setsockopt (s, SOL_SOCKET, SO_REUSEADDR, (const char*) &flag,
                sizeof (int));
        wsa_assert (rc != SOCKET_ERROR);
#else
        rc = setsockopt (s, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof (int));
        errno_assert (rc == 0);
#endif

        rc = ::bind (s, tcp_addr->src_addr (), tcp_addr->src_addrlen ());
        if (rc == -1)
            return -1;
    }

    //  Connect to the remote peer.
    rc = ::connect (s, tcp_addr->addr (), tcp_addr->addrlen ());

    //  Connect was successful immediately.
    if (rc == 0)
        return 0;

    //  Translate error codes indicating asynchronous connect has been
    //  launched to a uniform EINPROGRESS.
#ifdef ZMQ_HAVE_WINDOWS
    const int last_error = WSAGetLastError();
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

zmq::fd_t zmq::tcp_connecter_t::connect ()
{
    //  Async connect has finished. Check whether an error occurred
    int err = 0;
#ifdef ZMQ_HAVE_HPUX
    int len = sizeof err;
#else
    socklen_t len = sizeof err;
#endif

    const int rc = getsockopt (s, SOL_SOCKET, SO_ERROR, (char*) &err, &len);

    //  Assert if the error was caused by 0MQ bug.
    //  Networking problems are OK. No need to assert.
#ifdef ZMQ_HAVE_WINDOWS
    zmq_assert (rc == 0);
    if (err != 0) {
        if (err == WSAEBADF ||
            err == WSAENOPROTOOPT ||
            err == WSAENOTSOCK ||
            err == WSAENOBUFS)
        {
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
        errno_assert (
            errno != EBADF &&
            errno != ENOPROTOOPT &&
            errno != ENOTSOCK &&
            errno != ENOBUFS);
        return retired_fd;
    }
#endif

    //  Return the newly connected socket.
    const fd_t result = s;
    s = retired_fd;
    return result;
}

void zmq::tcp_connecter_t::close ()
{
    zmq_assert (s != retired_fd);
#ifdef ZMQ_HAVE_WINDOWS
    const int rc = closesocket (s);
    wsa_assert (rc != SOCKET_ERROR);
#else
    const int rc = ::close (s);
    errno_assert (rc == 0);
#endif
    socket->event_closed (endpoint, (int) s);
    s = retired_fd;
}
