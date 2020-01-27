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
    stream_connecter_base_t (
      io_thread_, session_, options_, addr_, delayed_start_),
    _proxy_addr (proxy_addr_),
    _auth_method (socks_no_auth_required),
    _status (unplugged)
{
    zmq_assert (_addr->protocol == protocol_name::tcp);
    _proxy_addr->to_string (_endpoint);
}

zmq::socks_connecter_t::~socks_connecter_t ()
{
    LIBZMQ_DELETE (_proxy_addr);
}

void zmq::socks_connecter_t::set_auth_method_none ()
{
    _auth_method = socks_no_auth_required;
    _auth_username.clear ();
    _auth_password.clear ();
}

void zmq::socks_connecter_t::set_auth_method_basic (
  const std::string &username_, const std::string &password_)
{
    _auth_method = socks_basic_auth;
    _auth_username = username_;
    _auth_password = password_;
}

void zmq::socks_connecter_t::in_event ()
{
    int expected_status = -1;
    zmq_assert (_status != unplugged);

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
                if (choice.method == socks_basic_auth)
                    expected_status = sending_basic_auth_request;
                else
                    expected_status = sending_request;
            }
        }
    } else if (_status == waiting_for_auth_response) {
        int rc = _auth_response_decoder.input (_s);
        if (rc == 0 || rc == -1)
            error ();
        else if (_auth_response_decoder.message_ready ()) {
            const socks_auth_response_t auth_response =
              _auth_response_decoder.decode ();
            rc = process_server_response (auth_response);
            if (rc == -1)
                error ();
            else {
                expected_status = sending_request;
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
                rm_handle ();
                create_engine (
                  _s, get_socket_name<tcp_address_t> (_s, socket_end_local));
                _s = -1;
                _status = unplugged;
            }
        }
    } else
        error ();

    if (expected_status == sending_basic_auth_request) {
        _basic_auth_request_encoder.encode (
          socks_basic_auth_request_t (_auth_username, _auth_password));
        reset_pollin (_handle);
        set_pollout (_handle);
        _status = sending_basic_auth_request;
    } else if (expected_status == sending_request) {
        std::string hostname;
        uint16_t port = 0;
        if (parse_address (_addr->address, hostname, port) == -1)
            error ();
        else {
            _request_encoder.encode (socks_request_t (1, hostname, port));
            reset_pollin (_handle);
            set_pollout (_handle);
            _status = sending_request;
        }
    }
}

void zmq::socks_connecter_t::out_event ()
{
    zmq_assert (
      _status == waiting_for_proxy_connection || _status == sending_greeting
      || _status == sending_basic_auth_request || _status == sending_request);

    if (_status == waiting_for_proxy_connection) {
        const int rc = static_cast<int> (check_proxy_connection ());
        if (rc == -1)
            error ();
        else {
            _greeting_encoder.encode (socks_greeting_t (_auth_method));
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
    } else if (_status == sending_basic_auth_request) {
        zmq_assert (_basic_auth_request_encoder.has_pending_data ());
        const int rc = _basic_auth_request_encoder.output (_s);
        if (rc == -1 || rc == 0)
            error ();
        else if (!_basic_auth_request_encoder.has_pending_data ()) {
            reset_pollout (_handle);
            set_pollin (_handle);
            _status = waiting_for_auth_response;
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

void zmq::socks_connecter_t::start_connecting ()
{
    zmq_assert (_status == unplugged);

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
        _socket->event_connect_delayed (
          make_unconnected_connect_endpoint_pair (_endpoint), zmq_errno ());
    }
    //  Handle any other error condition by eventual reconnect.
    else {
        if (_s != retired_fd)
            close ();
        add_reconnect_timer ();
    }
}

int zmq::socks_connecter_t::process_server_response (
  const socks_choice_t &response_)
{
    return response_.method == socks_no_auth_required
               || response_.method == socks_basic_auth
             ? 0
             : -1;
}

int zmq::socks_connecter_t::process_server_response (
  const socks_response_t &response_)
{
    return response_.response_code == 0 ? 0 : -1;
}

int zmq::socks_connecter_t::process_server_response (
  const socks_auth_response_t &response_)
{
    return response_.response_code == 0 ? 0 : -1;
}

void zmq::socks_connecter_t::error ()
{
    rm_fd (_handle);
    close ();
    _greeting_encoder.reset ();
    _choice_decoder.reset ();
    _basic_auth_request_encoder.reset ();
    _auth_response_decoder.reset ();
    _request_encoder.reset ();
    _response_decoder.reset ();
    _status = unplugged;
    add_reconnect_timer ();
}

int zmq::socks_connecter_t::connect_to_proxy ()
{
    zmq_assert (_s == retired_fd);

    //  Resolve the address
    if (_proxy_addr->resolved.tcp_addr != NULL) {
        LIBZMQ_DELETE (_proxy_addr->resolved.tcp_addr);
    }

    _proxy_addr->resolved.tcp_addr = new (std::nothrow) tcp_address_t ();
    alloc_assert (_proxy_addr->resolved.tcp_addr);
    //  Automatic fallback to ipv4 is disabled here since this was the existing
    //  behaviour, however I don't see a real reason for this. Maybe this can
    //  be changed to true (and then the parameter can be removed entirely).
    _s = tcp_open_socket (_proxy_addr->address.c_str (), options, false, false,
                          _proxy_addr->resolved.tcp_addr);
    if (_s == retired_fd) {
        //  TODO we should emit some event in this case!
        LIBZMQ_DELETE (_proxy_addr->resolved.tcp_addr);
        return -1;
    }
    zmq_assert (_proxy_addr->resolved.tcp_addr != NULL);

    // Set the socket to non-blocking mode so that we get async connect().
    unblock_socket (_s);

    const tcp_address_t *const tcp_addr = _proxy_addr->resolved.tcp_addr;

    int rc;

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

zmq::fd_t zmq::socks_connecter_t::check_proxy_connection () const
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
