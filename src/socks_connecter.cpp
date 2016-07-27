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
#include "socks_connecter.hpp"
#include "stream_engine.hpp"
#include "random.hpp"
#include "err.hpp"
#include "ip.hpp"
#include "tcp.hpp"
#include "address.hpp"
#include "tcp_address.hpp"
#include "session_base.hpp"
#include "socks.hpp"

#ifndef ZMQ_HAVE_WINDOWS
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#endif

zmq::socks_connecter_t::socks_connecter_t (class io_thread_t *io_thread_,
      class session_base_t *session_, const options_t &options_,
      address_t *addr_, address_t *proxy_addr_, bool delayed_start_) :
    own_t (io_thread_, options_),
    io_object_t (io_thread_),
    addr (addr_),
    proxy_addr (proxy_addr_),
    status (unplugged),
    s (retired_fd),
    handle((handle_t)NULL),
    handle_valid(false),
    delayed_start (delayed_start_),
    timer_started(false),
    session (session_),
    current_reconnect_ivl (options.reconnect_ivl)
{
    zmq_assert (addr);
    zmq_assert (addr->protocol == "tcp");
    proxy_addr->to_string (endpoint);
    socket = session->get_socket ();
}

zmq::socks_connecter_t::~socks_connecter_t ()
{
    zmq_assert (s == retired_fd);
    LIBZMQ_DELETE(proxy_addr);
}

void zmq::socks_connecter_t::process_plug ()
{
    if (delayed_start)
        start_timer ();
    else
        initiate_connect ();
}

void zmq::socks_connecter_t::process_term (int linger_)
{
    switch (status) {
        case unplugged:
            break;
        case waiting_for_reconnect_time:
            cancel_timer (reconnect_timer_id);
            break;
        case waiting_for_proxy_connection:
        case sending_greeting:
        case waiting_for_choice:
        case sending_request:
        case waiting_for_response:
            rm_fd (handle);
            if (s != retired_fd)
                close ();
            break;
    }

    own_t::process_term (linger_);
}

void zmq::socks_connecter_t::in_event ()
{
    zmq_assert (status != unplugged
             && status != waiting_for_reconnect_time);

    if (status == waiting_for_choice) {
        int rc = choice_decoder.input (s);
        if (rc == 0 || rc == -1)
            error ();
        else
        if (choice_decoder.message_ready ()) {
             const socks_choice_t choice = choice_decoder.decode ();
             rc = process_server_response (choice);
             if (rc == -1)
                 error ();
             else {
                 std::string hostname = "";
                 uint16_t port = 0;
                 if (parse_address (addr->address, hostname, port) == -1)
                     error ();
                 else {
                     request_encoder.encode (
                         socks_request_t (1, hostname, port));
                     reset_pollin (handle);
                     set_pollout (handle);
                     status = sending_request;
                 }
             }
        }
    }
    else
    if (status == waiting_for_response) {
        int rc = response_decoder.input (s);
        if (rc == 0 || rc == -1)
            error ();
        else
        if (response_decoder.message_ready ()) {
            const socks_response_t response = response_decoder.decode ();
            rc = process_server_response (response);
            if (rc == -1)
                error ();
            else {
                //  Create the engine object for this connection.
                stream_engine_t *engine = new (std::nothrow)
                    stream_engine_t (s, options, endpoint);
                alloc_assert (engine);

                //  Attach the engine to the corresponding session object.
                send_attach (session, engine);

                socket->event_connected (endpoint, (int) s);

                rm_fd (handle);
                s = -1;
                status = unplugged;

                //  Shut the connecter down.
                terminate ();
            }
        }
    }
    else
        error ();
}

void zmq::socks_connecter_t::out_event ()
{
    zmq_assert (status == waiting_for_proxy_connection
             || status == sending_greeting
             || status == sending_request);

    if (status == waiting_for_proxy_connection) {
        const int rc = (int) check_proxy_connection ();
        if (rc == -1)
            error ();
        else {
            greeting_encoder.encode (
                socks_greeting_t (socks_no_auth_required));
            status = sending_greeting;
        }
    }
    else
    if (status == sending_greeting) {
        zmq_assert (greeting_encoder.has_pending_data ());
        const int rc = greeting_encoder.output (s);
        if (rc == -1 || rc == 0)
            error ();
        else
        if (!greeting_encoder.has_pending_data ()) {
            reset_pollout (handle);
            set_pollin (handle);
            status = waiting_for_choice;
        }
    }
    else {
        zmq_assert (request_encoder.has_pending_data ());
        const int rc = request_encoder.output (s);
        if (rc == -1 || rc == 0)
            error ();
        else
        if (!request_encoder.has_pending_data ()) {
            reset_pollout (handle);
            set_pollin (handle);
            status = waiting_for_response;
        }
    }
}

void zmq::socks_connecter_t::initiate_connect ()
{
    //  Open the connecting socket.
    const int rc = connect_to_proxy ();

    //  Connect may succeed in synchronous manner.
    if (rc == 0) {
        handle = add_fd (s);
        set_pollout (handle);
        status = sending_greeting;
    }
    //  Connection establishment may be delayed. Poll for its completion.
    else
    if (errno == EINPROGRESS) {
        handle = add_fd (s);
        set_pollout (handle);
        status = waiting_for_proxy_connection;
        socket->event_connect_delayed (endpoint, zmq_errno ());
    }
    //  Handle any other error condition by eventual reconnect.
    else {
        if (s != retired_fd)
            close ();
        start_timer ();
    }
}

int zmq::socks_connecter_t::process_server_response (
        const socks_choice_t &response)
{
    //  We do not support any authentication method for now.
    return response.method == 0? 0: -1;
}

int zmq::socks_connecter_t::process_server_response (
        const socks_response_t &response)
{
    return response.response_code == 0? 0: -1;
}

void zmq::socks_connecter_t::timer_event (int id_)
{
    zmq_assert (status == waiting_for_reconnect_time);
    zmq_assert (id_ == reconnect_timer_id);
    initiate_connect ();
}

void zmq::socks_connecter_t::error ()
{
    rm_fd (handle);
    close ();
    greeting_encoder.reset ();
    choice_decoder.reset ();
    request_encoder.reset ();
    response_decoder.reset ();
    start_timer ();
}

void zmq::socks_connecter_t::start_timer ()
{
    const int interval = get_new_reconnect_ivl ();
    add_timer (interval, reconnect_timer_id);
    status = waiting_for_reconnect_time;
    socket->event_connect_retried (endpoint, interval);
}

int zmq::socks_connecter_t::get_new_reconnect_ivl ()
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

int zmq::socks_connecter_t::connect_to_proxy ()
{
    zmq_assert (s == retired_fd);

    //  Resolve the address
    LIBZMQ_DELETE(proxy_addr->resolved.tcp_addr);
    proxy_addr->resolved.tcp_addr = new (std::nothrow) tcp_address_t ();
    alloc_assert (proxy_addr->resolved.tcp_addr);

    int rc = proxy_addr->resolved.tcp_addr->resolve (
        proxy_addr->address.c_str (), false, options.ipv6);
    if (rc != 0) {
        LIBZMQ_DELETE(proxy_addr->resolved.tcp_addr);
        return -1;
    }
    zmq_assert (proxy_addr->resolved.tcp_addr != NULL);
    const tcp_address_t *tcp_addr = proxy_addr->resolved.tcp_addr;

    //  Create the socket.
    s = open_socket (tcp_addr->family (), SOCK_STREAM, IPPROTO_TCP);
#ifdef ZMQ_HAVE_WINDOWS
    if (s == INVALID_SOCKET)
        return -1;
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
        rc = ::bind (s, tcp_addr->src_addr (), tcp_addr->src_addrlen ());
        if (rc == -1) {
            close ();
            return -1;
        }
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
    else {
        errno = wsa_error_to_errno (last_error);
        close ();
    }
#else
    if (errno == EINTR)
        errno = EINPROGRESS;
#endif
    return -1;
}

zmq::fd_t zmq::socks_connecter_t::check_proxy_connection ()
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
        wsa_assert (err == WSAECONNREFUSED
                 || err == WSAETIMEDOUT
                 || err == WSAECONNABORTED
                 || err == WSAEHOSTUNREACH
                 || err == WSAENETUNREACH
                 || err == WSAENETDOWN
                 || err == WSAEACCES
                 || err == WSAEINVAL
                 || err == WSAEADDRINUSE);
        return -1;
    }
#else
    //  Following code should handle both Berkeley-derived socket
    //  implementations and Solaris.
    if (rc == -1)
        err = errno;
    if (err != 0) {
        errno = err;
        errno_assert (
            errno == ECONNREFUSED ||
            errno == ECONNRESET ||
            errno == ETIMEDOUT ||
            errno == EHOSTUNREACH ||
            errno == ENETUNREACH ||
            errno == ENETDOWN ||
            errno == EINVAL);
        return -1;
    }
#endif

    tune_tcp_socket (s);
    tune_tcp_keepalives (s, options.tcp_keepalive, options.tcp_keepalive_cnt,
        options.tcp_keepalive_idle, options.tcp_keepalive_intvl);

    return 0;
}

void zmq::socks_connecter_t::close ()
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

int zmq::socks_connecter_t::parse_address (
        const std::string &address_, std::string &hostname_, uint16_t &port_)
{
    //  Find the ':' at end that separates address from the port number.
    const size_t idx = address_.rfind (':');
    if (idx == std::string::npos) {
        errno = EINVAL;
        return -1;
    }

    //  Extract hostname
    if (idx < 2 || address_ [0] != '[' || address_ [idx - 1] != ']')
        hostname_ = address_.substr (0, idx);
    else
        hostname_ = address_.substr (1, idx - 2);

    //  Separate the hostname/port.
    const std::string port_str = address_.substr (idx + 1);
    //  Parse the port number (0 is not a valid port).
    port_ = (uint16_t) atoi (port_str.c_str ());
    if (port_ == 0) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}
