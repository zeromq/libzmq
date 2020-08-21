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

#ifdef ZMQ_USE_NSS
#include <secoid.h>
#include <sechash.h>
#define SHA_DIGEST_LENGTH 20
#elif defined ZMQ_USE_BUILTIN_SHA1
#include "../external/sha1/sha1.h"
#elif defined ZMQ_USE_GNUTLS
#define SHA_DIGEST_LENGTH 20
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#endif

#if !defined ZMQ_HAVE_WINDOWS
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#ifdef ZMQ_HAVE_VXWORKS
#include <sockLib.h>
#endif
#endif

#include <cstring>

#include "compat.hpp"
#include "tcp.hpp"
#include "ws_engine.hpp"
#include "session_base.hpp"
#include "err.hpp"
#include "ip.hpp"
#include "random.hpp"
#include "ws_decoder.hpp"
#include "ws_encoder.hpp"
#include "null_mechanism.hpp"
#include "plain_server.hpp"
#include "plain_client.hpp"

#ifdef ZMQ_HAVE_CURVE
#include "curve_client.hpp"
#include "curve_server.hpp"
#endif

//  OSX uses a different name for this socket option
#ifndef IPV6_ADD_MEMBERSHIP
#define IPV6_ADD_MEMBERSHIP IPV6_JOIN_GROUP
#endif

#ifdef __APPLE__
#include <TargetConditionals.h>
#endif

static int
encode_base64 (const unsigned char *in_, int in_len_, char *out_, int out_len_);

static void compute_accept_key (char *key_,
                                unsigned char hash_[SHA_DIGEST_LENGTH]);

zmq::ws_engine_t::ws_engine_t (fd_t fd_,
                               const options_t &options_,
                               const endpoint_uri_pair_t &endpoint_uri_pair_,
                               const ws_address_t &address_,
                               bool client_) :
    stream_engine_base_t (fd_, options_, endpoint_uri_pair_, true),
    _client (client_),
    _address (address_),
    _client_handshake_state (client_handshake_initial),
    _server_handshake_state (handshake_initial),
    _header_name_position (0),
    _header_value_position (0),
    _header_upgrade_websocket (false),
    _header_connection_upgrade (false),
    _heartbeat_timeout (0)
{
    memset (_websocket_key, 0, MAX_HEADER_VALUE_LENGTH + 1);
    memset (_websocket_accept, 0, MAX_HEADER_VALUE_LENGTH + 1);
    memset (_websocket_protocol, 0, 256);

    _next_msg = &ws_engine_t::next_handshake_command;
    _process_msg = &ws_engine_t::process_handshake_command;
    _close_msg.init ();

    if (_options.heartbeat_interval > 0) {
        _heartbeat_timeout = _options.heartbeat_timeout;
        if (_heartbeat_timeout == -1)
            _heartbeat_timeout = _options.heartbeat_interval;
    }
}

zmq::ws_engine_t::~ws_engine_t ()
{
    _close_msg.close ();
}

void zmq::ws_engine_t::start_ws_handshake ()
{
    if (_client) {
        const char *protocol;
        if (_options.mechanism == ZMQ_NULL)
            protocol = "ZWS2.0/NULL,ZWS2.0";
        else if (_options.mechanism == ZMQ_PLAIN)
            protocol = "ZWS2.0/PLAIN";
#ifdef ZMQ_HAVE_CURVE
        else if (_options.mechanism == ZMQ_CURVE)
            protocol = "ZWS2.0/CURVE";
#endif
        else {
            // Avoid unitialized variable error breaking UWP build
            protocol = "";
            assert (false);
        }

        unsigned char nonce[16];
        int *p = reinterpret_cast<int *> (nonce);

        // The nonce doesn't have to be secure one, it is just use to avoid proxy cache
        *p = zmq::generate_random ();
        *(p + 1) = zmq::generate_random ();
        *(p + 2) = zmq::generate_random ();
        *(p + 3) = zmq::generate_random ();

        int size =
          encode_base64 (nonce, 16, _websocket_key, MAX_HEADER_VALUE_LENGTH);
        assert (size > 0);

        size = snprintf (
          reinterpret_cast<char *> (_write_buffer), WS_BUFFER_SIZE,
          "GET %s HTTP/1.1\r\n"
          "Host: %s\r\n"
          "Upgrade: websocket\r\n"
          "Connection: Upgrade\r\n"
          "Sec-WebSocket-Key: %s\r\n"
          "Sec-WebSocket-Protocol: %s\r\n"
          "Sec-WebSocket-Version: 13\r\n\r\n",
          _address.path (), _address.host (), _websocket_key, protocol);
        assert (size > 0 && size < WS_BUFFER_SIZE);
        _outpos = _write_buffer;
        _outsize = size;
        set_pollout ();
    }
}

void zmq::ws_engine_t::plug_internal ()
{
    start_ws_handshake ();
    set_pollin ();
    in_event ();
}

int zmq::ws_engine_t::routing_id_msg (msg_t *msg_)
{
    const int rc = msg_->init_size (_options.routing_id_size);
    errno_assert (rc == 0);
    if (_options.routing_id_size > 0)
        memcpy (msg_->data (), _options.routing_id, _options.routing_id_size);
    _next_msg = &ws_engine_t::pull_msg_from_session;

    return 0;
}

int zmq::ws_engine_t::process_routing_id_msg (msg_t *msg_)
{
    if (_options.recv_routing_id) {
        msg_->set_flags (msg_t::routing_id);
        const int rc = session ()->push_msg (msg_);
        errno_assert (rc == 0);
    } else {
        int rc = msg_->close ();
        errno_assert (rc == 0);
        rc = msg_->init ();
        errno_assert (rc == 0);
    }

    _process_msg = &ws_engine_t::push_msg_to_session;

    return 0;
}

bool zmq::ws_engine_t::select_protocol (const char *protocol_)
{
    if (_options.mechanism == ZMQ_NULL && (strcmp ("ZWS2.0", protocol_) == 0)) {
        _next_msg = static_cast<int (stream_engine_base_t::*) (msg_t *)> (
          &ws_engine_t::routing_id_msg);
        _process_msg = static_cast<int (stream_engine_base_t::*) (msg_t *)> (
          &ws_engine_t::process_routing_id_msg);

        // No mechanism in place, enabling heartbeat
        if (_options.heartbeat_interval > 0 && !_has_heartbeat_timer) {
            add_timer (_options.heartbeat_interval, heartbeat_ivl_timer_id);
            _has_heartbeat_timer = true;
        }

        return true;
    }
    if (_options.mechanism == ZMQ_NULL
        && strcmp ("ZWS2.0/NULL", protocol_) == 0) {
        _mechanism = new (std::nothrow)
          null_mechanism_t (session (), _peer_address, _options);
        alloc_assert (_mechanism);
        return true;
    } else if (_options.mechanism == ZMQ_PLAIN
               && strcmp ("ZWS2.0/PLAIN", protocol_) == 0) {
        if (_options.as_server)
            _mechanism = new (std::nothrow)
              plain_server_t (session (), _peer_address, _options);
        else
            _mechanism =
              new (std::nothrow) plain_client_t (session (), _options);
        alloc_assert (_mechanism);
        return true;
    }
#ifdef ZMQ_HAVE_CURVE
    else if (_options.mechanism == ZMQ_CURVE
             && strcmp ("ZWS2.0/CURVE", protocol_) == 0) {
        if (_options.as_server)
            _mechanism = new (std::nothrow)
              curve_server_t (session (), _peer_address, _options, false);
        else
            _mechanism =
              new (std::nothrow) curve_client_t (session (), _options, false);
        alloc_assert (_mechanism);
        return true;
    }
#endif

    return false;
}

bool zmq::ws_engine_t::handshake ()
{
    bool complete;

    if (_client)
        complete = client_handshake ();
    else
        complete = server_handshake ();

    if (complete) {
        _encoder =
          new (std::nothrow) ws_encoder_t (_options.out_batch_size, _client);
        alloc_assert (_encoder);

        _decoder = new (std::nothrow)
          ws_decoder_t (_options.in_batch_size, _options.maxmsgsize,
                        _options.zero_copy, !_client);
        alloc_assert (_decoder);

        socket ()->event_handshake_succeeded (_endpoint_uri_pair, 0);

        set_pollout ();
    }

    return complete;
}

bool zmq::ws_engine_t::server_handshake ()
{
    const int nbytes = read (_read_buffer, WS_BUFFER_SIZE);
    if (nbytes == -1) {
        if (errno != EAGAIN)
            error (zmq::i_engine::connection_error);
        return false;
    }

    _inpos = _read_buffer;
    _insize = nbytes;

    while (_insize > 0) {
        const char c = static_cast<char> (*_inpos);

        switch (_server_handshake_state) {
            case handshake_initial:
                if (c == 'G')
                    _server_handshake_state = request_line_G;
                else
                    _server_handshake_state = handshake_error;
                break;
            case request_line_G:
                if (c == 'E')
                    _server_handshake_state = request_line_GE;
                else
                    _server_handshake_state = handshake_error;
                break;
            case request_line_GE:
                if (c == 'T')
                    _server_handshake_state = request_line_GET;
                else
                    _server_handshake_state = handshake_error;
                break;
            case request_line_GET:
                if (c == ' ')
                    _server_handshake_state = request_line_GET_space;
                else
                    _server_handshake_state = handshake_error;
                break;
            case request_line_GET_space:
                if (c == '\r' || c == '\n')
                    _server_handshake_state = handshake_error;
                // TODO: instead of check what is not allowed check what is allowed
                if (c != ' ')
                    _server_handshake_state = request_line_resource;
                else
                    _server_handshake_state = request_line_GET_space;
                break;
            case request_line_resource:
                if (c == '\r' || c == '\n')
                    _server_handshake_state = handshake_error;
                else if (c == ' ')
                    _server_handshake_state = request_line_resource_space;
                else
                    _server_handshake_state = request_line_resource;
                break;
            case request_line_resource_space:
                if (c == 'H')
                    _server_handshake_state = request_line_H;
                else
                    _server_handshake_state = handshake_error;
                break;
            case request_line_H:
                if (c == 'T')
                    _server_handshake_state = request_line_HT;
                else
                    _server_handshake_state = handshake_error;
                break;
            case request_line_HT:
                if (c == 'T')
                    _server_handshake_state = request_line_HTT;
                else
                    _server_handshake_state = handshake_error;
                break;
            case request_line_HTT:
                if (c == 'P')
                    _server_handshake_state = request_line_HTTP;
                else
                    _server_handshake_state = handshake_error;
                break;
            case request_line_HTTP:
                if (c == '/')
                    _server_handshake_state = request_line_HTTP_slash;
                else
                    _server_handshake_state = handshake_error;
                break;
            case request_line_HTTP_slash:
                if (c == '1')
                    _server_handshake_state = request_line_HTTP_slash_1;
                else
                    _server_handshake_state = handshake_error;
                break;
            case request_line_HTTP_slash_1:
                if (c == '.')
                    _server_handshake_state = request_line_HTTP_slash_1_dot;
                else
                    _server_handshake_state = handshake_error;
                break;
            case request_line_HTTP_slash_1_dot:
                if (c == '1')
                    _server_handshake_state = request_line_HTTP_slash_1_dot_1;
                else
                    _server_handshake_state = handshake_error;
                break;
            case request_line_HTTP_slash_1_dot_1:
                if (c == '\r')
                    _server_handshake_state = request_line_cr;
                else
                    _server_handshake_state = handshake_error;
                break;
            case request_line_cr:
                if (c == '\n')
                    _server_handshake_state = header_field_begin_name;
                else
                    _server_handshake_state = handshake_error;
                break;
            case header_field_begin_name:
                switch (c) {
                    case '\r':
                        _server_handshake_state = handshake_end_line_cr;
                        break;
                    case '\n':
                        _server_handshake_state = handshake_error;
                        break;
                    default:
                        _header_name[0] = c;
                        _header_name_position = 1;
                        _server_handshake_state = header_field_name;
                        break;
                }
                break;
            case header_field_name:
                if (c == '\r' || c == '\n')
                    _server_handshake_state = handshake_error;
                else if (c == ':') {
                    _header_name[_header_name_position] = '\0';
                    _server_handshake_state = header_field_colon;
                } else if (_header_name_position + 1 > MAX_HEADER_NAME_LENGTH)
                    _server_handshake_state = handshake_error;
                else {
                    _header_name[_header_name_position] = c;
                    _header_name_position++;
                    _server_handshake_state = header_field_name;
                }
                break;
            case header_field_colon:
            case header_field_value_trailing_space:
                if (c == '\n')
                    _server_handshake_state = handshake_error;
                else if (c == '\r')
                    _server_handshake_state = header_field_cr;
                else if (c == ' ')
                    _server_handshake_state = header_field_value_trailing_space;
                else {
                    _header_value[0] = c;
                    _header_value_position = 1;
                    _server_handshake_state = header_field_value;
                }
                break;
            case header_field_value:
                if (c == '\n')
                    _server_handshake_state = handshake_error;
                else if (c == '\r') {
                    _header_value[_header_value_position] = '\0';

                    if (strcasecmp ("upgrade", _header_name) == 0)
                        _header_upgrade_websocket =
                          strcasecmp ("websocket", _header_value) == 0;
                    else if (strcasecmp ("connection", _header_name) == 0)
                        _header_connection_upgrade =
                          strcasecmp ("upgrade", _header_value) == 0;
                    else if (strcasecmp ("Sec-WebSocket-Key", _header_name)
                             == 0)
                        strcpy_s (_websocket_key, _header_value);
                    else if (strcasecmp ("Sec-WebSocket-Protocol", _header_name)
                             == 0) {
                        // Currently only the ZWS2.0 is supported
                        // Sec-WebSocket-Protocol can appear multiple times or be a comma separated list
                        // if _websocket_protocol is already set we skip the check
                        if (_websocket_protocol[0] == '\0') {
                            char *rest = 0;
                            char *p = strtok_r (_header_value, ",", &rest);
                            while (p != NULL) {
                                if (*p == ' ')
                                    p++;

                                if (select_protocol (p)) {
                                    strcpy_s (_websocket_protocol, p);
                                    break;
                                }

                                p = strtok_r (NULL, ",", &rest);
                            }
                        }
                    }

                    _server_handshake_state = header_field_cr;
                } else if (_header_value_position + 1 > MAX_HEADER_VALUE_LENGTH)
                    _server_handshake_state = handshake_error;
                else {
                    _header_value[_header_value_position] = c;
                    _header_value_position++;
                    _server_handshake_state = header_field_value;
                }
                break;
            case header_field_cr:
                if (c == '\n')
                    _server_handshake_state = header_field_begin_name;
                else
                    _server_handshake_state = handshake_error;
                break;
            case handshake_end_line_cr:
                if (c == '\n') {
                    if (_header_connection_upgrade && _header_upgrade_websocket
                        && _websocket_protocol[0] != '\0'
                        && _websocket_key[0] != '\0') {
                        _server_handshake_state = handshake_complete;

                        unsigned char hash[SHA_DIGEST_LENGTH];
                        compute_accept_key (_websocket_key, hash);

                        const int accept_key_len = encode_base64 (
                          hash, SHA_DIGEST_LENGTH, _websocket_accept,
                          MAX_HEADER_VALUE_LENGTH);
                        assert (accept_key_len > 0);
                        _websocket_accept[accept_key_len] = '\0';

                        const int written =
                          snprintf (reinterpret_cast<char *> (_write_buffer),
                                    WS_BUFFER_SIZE,
                                    "HTTP/1.1 101 Switching Protocols\r\n"
                                    "Upgrade: websocket\r\n"
                                    "Connection: Upgrade\r\n"
                                    "Sec-WebSocket-Accept: %s\r\n"
                                    "Sec-WebSocket-Protocol: %s\r\n"
                                    "\r\n",
                                    _websocket_accept, _websocket_protocol);
                        assert (written >= 0 && written < WS_BUFFER_SIZE);
                        _outpos = _write_buffer;
                        _outsize = written;

                        _inpos++;
                        _insize--;

                        return true;
                    }
                    _server_handshake_state = handshake_error;
                } else
                    _server_handshake_state = handshake_error;
                break;
            default:
                assert (false);
        }

        _inpos++;
        _insize--;

        if (_server_handshake_state == handshake_error) {
            // TODO: send bad request

            socket ()->event_handshake_failed_protocol (
              _endpoint_uri_pair, ZMQ_PROTOCOL_ERROR_WS_UNSPECIFIED);

            error (zmq::i_engine::protocol_error);
            return false;
        }
    }
    return false;
}

bool zmq::ws_engine_t::client_handshake ()
{
    const int nbytes = read (_read_buffer, WS_BUFFER_SIZE);
    if (nbytes == -1) {
        if (errno != EAGAIN)
            error (zmq::i_engine::connection_error);
        return false;
    }

    _inpos = _read_buffer;
    _insize = nbytes;

    while (_insize > 0) {
        const char c = static_cast<char> (*_inpos);

        switch (_client_handshake_state) {
            case client_handshake_initial:
                if (c == 'H')
                    _client_handshake_state = response_line_H;
                else
                    _client_handshake_state = client_handshake_error;
                break;
            case response_line_H:
                if (c == 'T')
                    _client_handshake_state = response_line_HT;
                else
                    _client_handshake_state = client_handshake_error;
                break;
            case response_line_HT:
                if (c == 'T')
                    _client_handshake_state = response_line_HTT;
                else
                    _client_handshake_state = client_handshake_error;
                break;
            case response_line_HTT:
                if (c == 'P')
                    _client_handshake_state = response_line_HTTP;
                else
                    _client_handshake_state = client_handshake_error;
                break;
            case response_line_HTTP:
                if (c == '/')
                    _client_handshake_state = response_line_HTTP_slash;
                else
                    _client_handshake_state = client_handshake_error;
                break;
            case response_line_HTTP_slash:
                if (c == '1')
                    _client_handshake_state = response_line_HTTP_slash_1;
                else
                    _client_handshake_state = client_handshake_error;
                break;
            case response_line_HTTP_slash_1:
                if (c == '.')
                    _client_handshake_state = response_line_HTTP_slash_1_dot;
                else
                    _client_handshake_state = client_handshake_error;
                break;
            case response_line_HTTP_slash_1_dot:
                if (c == '1')
                    _client_handshake_state = response_line_HTTP_slash_1_dot_1;
                else
                    _client_handshake_state = client_handshake_error;
                break;
            case response_line_HTTP_slash_1_dot_1:
                if (c == ' ')
                    _client_handshake_state =
                      response_line_HTTP_slash_1_dot_1_space;
                else
                    _client_handshake_state = client_handshake_error;
                break;
            case response_line_HTTP_slash_1_dot_1_space:
                if (c == ' ')
                    _client_handshake_state =
                      response_line_HTTP_slash_1_dot_1_space;
                else if (c == '1')
                    _client_handshake_state = response_line_status_1;
                else
                    _client_handshake_state = client_handshake_error;
                break;
            case response_line_status_1:
                if (c == '0')
                    _client_handshake_state = response_line_status_10;
                else
                    _client_handshake_state = client_handshake_error;
                break;
            case response_line_status_10:
                if (c == '1')
                    _client_handshake_state = response_line_status_101;
                else
                    _client_handshake_state = client_handshake_error;
                break;
            case response_line_status_101:
                if (c == ' ')
                    _client_handshake_state = response_line_status_101_space;
                else
                    _client_handshake_state = client_handshake_error;
                break;
            case response_line_status_101_space:
                if (c == ' ')
                    _client_handshake_state = response_line_status_101_space;
                else if (c == 'S')
                    _client_handshake_state = response_line_s;
                else
                    _client_handshake_state = client_handshake_error;
                break;
            case response_line_s:
                if (c == 'w')
                    _client_handshake_state = response_line_sw;
                else
                    _client_handshake_state = client_handshake_error;
                break;
            case response_line_sw:
                if (c == 'i')
                    _client_handshake_state = response_line_swi;
                else
                    _client_handshake_state = client_handshake_error;
                break;
            case response_line_swi:
                if (c == 't')
                    _client_handshake_state = response_line_swit;
                else
                    _client_handshake_state = client_handshake_error;
                break;
            case response_line_swit:
                if (c == 'c')
                    _client_handshake_state = response_line_switc;
                else
                    _client_handshake_state = client_handshake_error;
                break;
            case response_line_switc:
                if (c == 'h')
                    _client_handshake_state = response_line_switch;
                else
                    _client_handshake_state = client_handshake_error;
                break;
            case response_line_switch:
                if (c == 'i')
                    _client_handshake_state = response_line_switchi;
                else
                    _client_handshake_state = client_handshake_error;
                break;
            case response_line_switchi:
                if (c == 'n')
                    _client_handshake_state = response_line_switchin;
                else
                    _client_handshake_state = client_handshake_error;
                break;
            case response_line_switchin:
                if (c == 'g')
                    _client_handshake_state = response_line_switching;
                else
                    _client_handshake_state = client_handshake_error;
                break;
            case response_line_switching:
                if (c == ' ')
                    _client_handshake_state = response_line_switching_space;
                else
                    _client_handshake_state = client_handshake_error;
                break;
            case response_line_switching_space:
                if (c == 'P')
                    _client_handshake_state = response_line_p;
                else
                    _client_handshake_state = client_handshake_error;
                break;
            case response_line_p:
                if (c == 'r')
                    _client_handshake_state = response_line_pr;
                else
                    _client_handshake_state = client_handshake_error;
                break;
            case response_line_pr:
                if (c == 'o')
                    _client_handshake_state = response_line_pro;
                else
                    _client_handshake_state = client_handshake_error;
                break;
            case response_line_pro:
                if (c == 't')
                    _client_handshake_state = response_line_prot;
                else
                    _client_handshake_state = client_handshake_error;
                break;
            case response_line_prot:
                if (c == 'o')
                    _client_handshake_state = response_line_proto;
                else
                    _client_handshake_state = client_handshake_error;
                break;
            case response_line_proto:
                if (c == 'c')
                    _client_handshake_state = response_line_protoc;
                else
                    _client_handshake_state = client_handshake_error;
                break;
            case response_line_protoc:
                if (c == 'o')
                    _client_handshake_state = response_line_protoco;
                else
                    _client_handshake_state = client_handshake_error;
                break;
            case response_line_protoco:
                if (c == 'l')
                    _client_handshake_state = response_line_protocol;
                else
                    _client_handshake_state = client_handshake_error;
                break;
            case response_line_protocol:
                if (c == 's')
                    _client_handshake_state = response_line_protocols;
                else
                    _client_handshake_state = client_handshake_error;
                break;
            case response_line_protocols:
                if (c == '\r')
                    _client_handshake_state = response_line_cr;
                else
                    _client_handshake_state = client_handshake_error;
                break;
            case response_line_cr:
                if (c == '\n')
                    _client_handshake_state = client_header_field_begin_name;
                else
                    _client_handshake_state = client_handshake_error;
                break;
            case client_header_field_begin_name:
                switch (c) {
                    case '\r':
                        _client_handshake_state = client_handshake_end_line_cr;
                        break;
                    case '\n':
                        _client_handshake_state = client_handshake_error;
                        break;
                    default:
                        _header_name[0] = c;
                        _header_name_position = 1;
                        _client_handshake_state = client_header_field_name;
                        break;
                }
                break;
            case client_header_field_name:
                if (c == '\r' || c == '\n')
                    _client_handshake_state = client_handshake_error;
                else if (c == ':') {
                    _header_name[_header_name_position] = '\0';
                    _client_handshake_state = client_header_field_colon;
                } else if (_header_name_position + 1 > MAX_HEADER_NAME_LENGTH)
                    _client_handshake_state = client_handshake_error;
                else {
                    _header_name[_header_name_position] = c;
                    _header_name_position++;
                    _client_handshake_state = client_header_field_name;
                }
                break;
            case client_header_field_colon:
            case client_header_field_value_trailing_space:
                if (c == '\n')
                    _client_handshake_state = client_handshake_error;
                else if (c == '\r')
                    _client_handshake_state = client_header_field_cr;
                else if (c == ' ')
                    _client_handshake_state =
                      client_header_field_value_trailing_space;
                else {
                    _header_value[0] = c;
                    _header_value_position = 1;
                    _client_handshake_state = client_header_field_value;
                }
                break;
            case client_header_field_value:
                if (c == '\n')
                    _client_handshake_state = client_handshake_error;
                else if (c == '\r') {
                    _header_value[_header_value_position] = '\0';

                    if (strcasecmp ("upgrade", _header_name) == 0)
                        _header_upgrade_websocket =
                          strcasecmp ("websocket", _header_value) == 0;
                    else if (strcasecmp ("connection", _header_name) == 0)
                        _header_connection_upgrade =
                          strcasecmp ("upgrade", _header_value) == 0;
                    else if (strcasecmp ("Sec-WebSocket-Accept", _header_name)
                             == 0)
                        strcpy_s (_websocket_accept, _header_value);
                    else if (strcasecmp ("Sec-WebSocket-Protocol", _header_name)
                             == 0) {
                        if (_mechanism) {
                            _client_handshake_state = client_handshake_error;
                            break;
                        }
                        if (select_protocol (_header_value))
                            strcpy_s (_websocket_protocol, _header_value);
                    }
                    _client_handshake_state = client_header_field_cr;
                } else if (_header_value_position + 1 > MAX_HEADER_VALUE_LENGTH)
                    _client_handshake_state = client_handshake_error;
                else {
                    _header_value[_header_value_position] = c;
                    _header_value_position++;
                    _client_handshake_state = client_header_field_value;
                }
                break;
            case client_header_field_cr:
                if (c == '\n')
                    _client_handshake_state = client_header_field_begin_name;
                else
                    _client_handshake_state = client_handshake_error;
                break;
            case client_handshake_end_line_cr:
                if (c == '\n') {
                    if (_header_connection_upgrade && _header_upgrade_websocket
                        && _websocket_protocol[0] != '\0'
                        && _websocket_accept[0] != '\0') {
                        _client_handshake_state = client_handshake_complete;

                        // TODO: validate accept key

                        _inpos++;
                        _insize--;

                        return true;
                    }
                    _client_handshake_state = client_handshake_error;
                } else
                    _client_handshake_state = client_handshake_error;
                break;
            default:
                assert (false);
        }

        _inpos++;
        _insize--;

        if (_client_handshake_state == client_handshake_error) {
            socket ()->event_handshake_failed_protocol (
              _endpoint_uri_pair, ZMQ_PROTOCOL_ERROR_WS_UNSPECIFIED);

            error (zmq::i_engine::protocol_error);
            return false;
        }
    }

    return false;
}

int zmq::ws_engine_t::decode_and_push (msg_t *msg_)
{
    zmq_assert (_mechanism != NULL);

    //  with WS engine, ping and pong commands are control messages and should not go through any mechanism
    if (msg_->is_ping () || msg_->is_pong () || msg_->is_close_cmd ()) {
        if (process_command_message (msg_) == -1)
            return -1;
    } else if (_mechanism->decode (msg_) == -1)
        return -1;

    if (_has_timeout_timer) {
        _has_timeout_timer = false;
        cancel_timer (heartbeat_timeout_timer_id);
    }

    if (msg_->flags () & msg_t::command && !msg_->is_ping ()
        && !msg_->is_pong () && !msg_->is_close_cmd ())
        process_command_message (msg_);

    if (_metadata)
        msg_->set_metadata (_metadata);
    if (session ()->push_msg (msg_) == -1) {
        if (errno == EAGAIN)
            _process_msg = &ws_engine_t::push_one_then_decode_and_push;
        return -1;
    }
    return 0;
}

int zmq::ws_engine_t::produce_close_message (msg_t *msg_)
{
    int rc = msg_->move (_close_msg);
    errno_assert (rc == 0);

    _next_msg = static_cast<int (stream_engine_base_t::*) (msg_t *)> (
      &ws_engine_t::produce_no_msg_after_close);

    return rc;
}

int zmq::ws_engine_t::produce_no_msg_after_close (msg_t *msg_)
{
    _next_msg = static_cast<int (stream_engine_base_t::*) (msg_t *)> (
      &ws_engine_t::close_connection_after_close);

    errno = EAGAIN;
    return -1;
}

int zmq::ws_engine_t::close_connection_after_close (msg_t *msg_)
{
    error (connection_error);
    errno = ECONNRESET;
    return -1;
}

int zmq::ws_engine_t::produce_ping_message (msg_t *msg_)
{
    int rc = msg_->init ();
    errno_assert (rc == 0);
    msg_->set_flags (msg_t::command | msg_t::ping);

    _next_msg = &ws_engine_t::pull_and_encode;
    if (!_has_timeout_timer && _heartbeat_timeout > 0) {
        add_timer (_heartbeat_timeout, heartbeat_timeout_timer_id);
        _has_timeout_timer = true;
    }

    return rc;
}


int zmq::ws_engine_t::produce_pong_message (msg_t *msg_)
{
    int rc = msg_->init ();
    errno_assert (rc == 0);
    msg_->set_flags (msg_t::command | msg_t::pong);

    _next_msg = &ws_engine_t::pull_and_encode;
    return rc;
}


int zmq::ws_engine_t::process_command_message (msg_t *msg_)
{
    if (msg_->is_ping ()) {
        _next_msg = static_cast<int (stream_engine_base_t::*) (msg_t *)> (
          &ws_engine_t::produce_pong_message);
        out_event ();
    } else if (msg_->is_close_cmd ()) {
        int rc = _close_msg.copy (*msg_);
        errno_assert (rc == 0);
        _next_msg = static_cast<int (stream_engine_base_t::*) (msg_t *)> (
          &ws_engine_t::produce_close_message);
        out_event ();
    }

    return 0;
}

static int
encode_base64 (const unsigned char *in_, int in_len_, char *out_, int out_len_)
{
    static const unsigned char base64enc_tab[65] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    int io = 0;
    uint32_t v = 0;
    int rem = 0;

    for (int ii = 0; ii < in_len_; ii++) {
        unsigned char ch;
        ch = in_[ii];
        v = (v << 8) | ch;
        rem += 8;
        while (rem >= 6) {
            rem -= 6;
            if (io >= out_len_)
                return -1; /* truncation is failure */
            out_[io++] = base64enc_tab[(v >> rem) & 63];
        }
    }
    if (rem) {
        v <<= (6 - rem);
        if (io >= out_len_)
            return -1; /* truncation is failure */
        out_[io++] = base64enc_tab[v & 63];
    }
    while (io & 3) {
        if (io >= out_len_)
            return -1; /* truncation is failure */
        out_[io++] = '=';
    }
    if (io >= out_len_)
        return -1; /* no room for null terminator */
    out_[io] = 0;
    return io;
}

static void compute_accept_key (char *key_, unsigned char *hash_)
{
    const char *magic_string = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
#ifdef ZMQ_USE_NSS
    unsigned int len;
    HASH_HashType type = HASH_GetHashTypeByOidTag (SEC_OID_SHA1);
    HASHContext *ctx = HASH_Create (type);
    assert (ctx);

    HASH_Begin (ctx);
    HASH_Update (ctx, (unsigned char *) key_, (unsigned int) strlen (key_));
    HASH_Update (ctx, (unsigned char *) magic_string,
                 (unsigned int) strlen (magic_string));
    HASH_End (ctx, hash_, &len, SHA_DIGEST_LENGTH);
    HASH_Destroy (ctx);
#elif defined ZMQ_USE_BUILTIN_SHA1
    sha1_ctxt ctx;
    SHA1_Init (&ctx);
    SHA1_Update (&ctx, (unsigned char *) key_, strlen (key_));
    SHA1_Update (&ctx, (unsigned char *) magic_string, strlen (magic_string));

    SHA1_Final (hash_, &ctx);
#elif defined ZMQ_USE_GNUTLS
    gnutls_hash_hd_t hd;
    gnutls_hash_init (&hd, GNUTLS_DIG_SHA1);
    gnutls_hash (hd, key_, strlen (key_));
    gnutls_hash (hd, magic_string, strlen (magic_string));
    gnutls_hash_deinit (hd, hash_);
#else
#error "No sha1 implementation set"
#endif
}
