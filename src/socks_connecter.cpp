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
#if defined ZMQ_HAVE_VXWORKS
#include <sockLib.h>
#endif
#endif

zmq::socks_connecter_t::socks_connecter_t (class io_thread_t *io_thread_,
                                           class session_base_t *session_,
                                           const options_t &options_,
                                           address_t *addr_,
                                           address_t *proxy_addr_,
                                           bool delayed_start_) :
    own_t (io_thread_, options_),
    io_object_t (io_thread_),
    _addr (addr_),
    _proxy_addr (proxy_addr_),
    _status (unplugged),
    _s (retired_fd),
    _handle (static_cast<handle_t> (NULL)),
    _handle_valid (false),
    _delayed_start (delayed_start_),
    _timer_started (false),
    _session (session_),
    _current_reconnect_ivl (options.reconnect_ivl)
{
    zmq_assert (_addr);
    zmq_assert (_addr->protocol == protocol_name::tcp);
    _proxy_addr->to_string (_endpoint);
    _socket = _session->get_socket ();
}

zmq::socks_connecter_t::~socks_connecter_t ()
{
    zmq_assert (_s == retired_fd);
    LIBZMQ_DELETE (_proxy_addr);
}

void zmq::socks_connecter_t::process_plug ()
{
    if (_delayed_start)
        start_timer ();
    else
        initiate_connect ();
}

void zmq::socks_connecter_t::process_term (int linger_)
{
    switch (_status) {
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
            rm_fd (_handle);
            if (_s != retired_fd)
                close ();
            break;
    }

    own_t::process_term (linger_);
}

void zmq::socks_connecter_t::in_event ()
{
    zmq_assert (_status != unplugged && _status != waiting_for_reconnect_time);

    if (_status == waiting_for_choice) {
        int rc = _choice_decoder.input (_s);
        if (rc == 0 || rc == -1)
            error ();
        else if (_choice_decoder.message_ready ()) {
            const socks_choice_t choice = _choice_decoder.decode ();
            rc = process_server_response (choice);
            if (rc == -1)
                error ();
            else {
                std::string hostname = "";
                uint16_t port = 0;
                if (parse_address (_addr->address, hostname, port) == -1)
                    error ();
                else {
                    _request_encoder.encode (
                      socks_request_t (1, hostname, port));
                    reset_pollin (_handle);
                    set_pollout (_handle);
                    _status = sending_request;
                }
            }
        }
    } else if (_status == waiting_for_response) {
        int rc = _response_decoder.input (_s);
        if (rc == 0 || rc == -1)
            error ();
        else if (_response_decoder.message_ready ()) {
            const socks_response_t response = _response_decoder.decode ();
            rc = process_server_response (response);
            if (rc == -1)
                error ();
            else {
                //  Create the engine object for this connection.
                stream_engine_t *engine =
                  new (std::nothrow) stream_engine_t (_s, options, _endpoint);
                alloc_assert (engine);

                //  Attach the engine to the corresponding session object.
                send_attach (_session, engine);

                _socket->event_connected (_endpoint, _s);

                rm_fd (_handle);
                _s = -1;
                _status = unplugged;

                //  Shut the connecter down.
                terminate ();
            }
        }
    } else
        error ();
}

void zmq::socks_connecter_t::out_event ()
{
    zmq_assert (_status == waiting_for_proxy_connection
                || _status == sending_greeting || _status == sending_request);

    if (_status == waiting_for_proxy_connection) {
        const int rc = static_cast<int> (check_proxy_connection ());
        if (rc == -1)
            error ();
        else {
            _greeting_encoder.encode (
              socks_greeting_t (socks_no_auth_required));
            _status = sending_greeting;
        }
    } else if (_status == sending_greeting) {
        zmq_assert (_greeting_encoder.has_pending_data ());
        const int rc = _greeting_encoder.output (_s);
        if (rc == -1 || rc == 0)
            error ();
        else if (!_greeting_encoder.has_pending_data ()) {
            reset_pollout (_handle);
            set_pollin (_handle);
            _status = waiting_for_choice;
        }
    } else {
        zmq_assert (_request_encoder.has_pending_data ());
        const int rc = _request_encoder.output (_s);
        if (rc == -1 || rc == 0)
            error ();
        else if (!_request_encoder.has_pending_data ()) {
            reset_pollout (_handle);
            set_pollin (_handle);
            _status = waiting_for_response;
        }
    }
}

void zmq::socks_connecter_t::initiate_connect ()
{
    //  Open the connecting socket.
    const int rc = connect_to_proxy ();

    //  Connect may succeed in synchronous manner.
    if (rc == 0) {
        _handle = add_fd (_s);
        set_pollout (_handle);
        _status = sending_greeting;
    }
    //  Connection establishment may be delayed. Poll for its completion.
    else if (errno == EINPROGRESS) {
        _handle = add_fd (_s);
        set_pollout (_handle);
        _status = waiting_for_proxy_connection;
        _socket->event_connect_delayed (_endpoint, zmq_errno ());
    }
    //  Handle any other error condition by eventual reconnect.
    else {
        if (_s != retired_fd)
            close ();
        start_timer ();
    }
}

int zmq::socks_connecter_t::process_server_response (
  const socks_choice_t &response_)
{
    //  We do not support any authentication method for now.
    return response_.method == 0 ? 0 : -1;
}

int zmq::socks_connecter_t::process_server_response (
  const socks_response_t &response_)
{
    return response_.response_code == 0 ? 0 : -1;
}

void zmq::socks_connecter_t::timer_event (int id_)
{
    zmq_assert (_status == waiting_for_reconnect_time);
    zmq_assert (id_ == reconnect_timer_id);
    initiate_connect ();
}

void zmq::socks_connecter_t::error ()
{
    rm_fd (_handle);
    close ();
    _greeting_encoder.reset ();
    _choice_decoder.reset ();
    _request_encoder.reset ();
    _response_decoder.reset ();
    start_timer ();
}

void zmq::socks_connecter_t::start_timer ()
{
    if (options.reconnect_ivl != -1) {
        const int interval = get_new_reconnect_ivl ();
        add_timer (interval, reconnect_timer_id);
        _status = waiting_for_reconnect_time;
        _socket->event_connect_retried (_endpoint, interval);
    }
}

int zmq::socks_connecter_t::get_new_reconnect_ivl ()
{
    //  The new interval is the current interval + random value.
    const int interval =
      _current_reconnect_ivl + generate_random () % options.reconnect_ivl;

    //  Only change the current reconnect interval  if the maximum reconnect
    //  interval was set and if it's larger than the reconnect interval.
    if (options.reconnect_ivl_max > 0
        && options.reconnect_ivl_max > options.reconnect_ivl)
        //  Calculate the next interval
        _current_reconnect_ivl =
          std::min (_current_reconnect_ivl * 2, options.reconnect_ivl_max);
    return interval;
}

int zmq::socks_connecter_t::connect_to_proxy ()
{
    zmq_assert (_s == retired_fd);

    //  Resolve the address
    LIBZMQ_DELETE (_proxy_addr->resolved.tcp_addr);
    _proxy_addr->resolved.tcp_addr = new (std::nothrow) tcp_address_t ();
    alloc_assert (_proxy_addr->resolved.tcp_addr);

    int rc = _proxy_addr->resolved.tcp_addr->resolve (
      _proxy_addr->address.c_str (), false, options.ipv6);
    if (rc != 0) {
        LIBZMQ_DELETE (_proxy_addr->resolved.tcp_addr);
        return -1;
    }
    zmq_assert (_proxy_addr->resolved.tcp_addr != NULL);
    const tcp_address_t *tcp_addr = _proxy_addr->resolved.tcp_addr;

    //  Create the socket.
    _s = open_socket (tcp_addr->family (), SOCK_STREAM, IPPROTO_TCP);
    if (_s == retired_fd)
        return -1;

    //  On some systems, IPv4 mapping in IPv6 sockets is disabled by default.
    //  Switch it on in such cases.
    if (tcp_addr->family () == AF_INET6)
        enable_ipv4_mapping (_s);

    // Set the IP Type-Of-Service priority for this socket
    if (options.tos != 0)
        set_ip_type_of_service (_s, options.tos);

    // Bind the socket to a device if applicable
    if (!options.bound_device.empty ())
        bind_to_device (_s, options.bound_device);

    // Set the socket to non-blocking mode so that we get async connect().
    unblock_socket (_s);

    //  Set the socket buffer limits for the underlying socket.
    if (options.sndbuf >= 0)
        set_tcp_send_buffer (_s, options.sndbuf);
    if (options.rcvbuf >= 0)
        set_tcp_receive_buffer (_s, options.rcvbuf);

    // Set the IP Type-Of-Service for the underlying socket
    if (options.tos != 0)
        set_ip_type_of_service (_s, options.tos);

    // Set a source address for conversations
    if (tcp_addr->has_src_addr ()) {
#if defined ZMQ_HAVE_VXWORKS
        rc = ::bind (_s, (sockaddr *) tcp_addr->src_addr (),
                     tcp_addr->src_addrlen ());
#else
        rc = ::bind (_s, tcp_addr->src_addr (), tcp_addr->src_addrlen ());
#endif
        if (rc == -1) {
            close ();
            return -1;
        }
    }

        //  Connect to the remote peer.
#if defined ZMQ_HAVE_VXWORKS
    rc = ::connect (_s, (sockaddr *) tcp_addr->addr (), tcp_addr->addrlen ());
#else
    rc = ::connect (_s, tcp_addr->addr (), tcp_addr->addrlen ());
#endif
    //  Connect was successful immediately.
    if (rc == 0)
        return 0;

        //  Translate error codes indicating asynchronous connect has been
        //  launched to a uniform EINPROGRESS.
#ifdef ZMQ_HAVE_WINDOWS
    const int last_error = WSAGetLastError ();
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
#if defined ZMQ_HAVE_HPUX || defined ZMQ_HAVE_VXWORKS
    int len = sizeof err;
#else
    socklen_t len = sizeof err;
#endif

    int rc = getsockopt (_s, SOL_SOCKET, SO_ERROR,
                         reinterpret_cast<char *> (&err), &len);

    //  Assert if the error was caused by 0MQ bug.
    //  Networking problems are OK. No need to assert.
#ifdef ZMQ_HAVE_WINDOWS
    zmq_assert (rc == 0);
    if (err != 0) {
        wsa_assert (err == WSAECONNREFUSED || err == WSAETIMEDOUT
                    || err == WSAECONNABORTED || err == WSAEHOSTUNREACH
                    || err == WSAENETUNREACH || err == WSAENETDOWN
                    || err == WSAEACCES || err == WSAEINVAL
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
        errno_assert (errno == ECONNREFUSED || errno == ECONNRESET
                      || errno == ETIMEDOUT || errno == EHOSTUNREACH
                      || errno == ENETUNREACH || errno == ENETDOWN
                      || errno == EINVAL);
        return -1;
    }
#endif

    rc = tune_tcp_socket (_s);
    rc = rc
         | tune_tcp_keepalives (
             _s, options.tcp_keepalive, options.tcp_keepalive_cnt,
             options.tcp_keepalive_idle, options.tcp_keepalive_intvl);
    if (rc != 0)
        return -1;

    return 0;
}

void zmq::socks_connecter_t::close ()
{
    zmq_assert (_s != retired_fd);
#ifdef ZMQ_HAVE_WINDOWS
    const int rc = closesocket (_s);
    wsa_assert (rc != SOCKET_ERROR);
#else
    const int rc = ::close (_s);
    errno_assert (rc == 0);
#endif
    _socket->event_closed (_endpoint, _s);
    _s = retired_fd;
}

int zmq::socks_connecter_t::parse_address (const std::string &address_,
                                           std::string &hostname_,
                                           uint16_t &port_)
{
    //  Find the ':' at end that separates address from the port number.
    const size_t idx = address_.rfind (':');
    if (idx == std::string::npos) {
        errno = EINVAL;
        return -1;
    }

    //  Extract hostname
    if (idx < 2 || address_[0] != '[' || address_[idx - 1] != ']')
        hostname_ = address_.substr (0, idx);
    else
        hostname_ = address_.substr (1, idx - 2);

    //  Separate the hostname/port.
    const std::string port_str = address_.substr (idx + 1);
    //  Parse the port number (0 is not a valid port).
    port_ = static_cast<uint16_t> (atoi (port_str.c_str ()));
    if (port_ == 0) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}
