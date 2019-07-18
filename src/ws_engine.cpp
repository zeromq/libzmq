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

#include "tcp.hpp"
#include "ws_engine.hpp"
#include "session_base.hpp"
#include "err.hpp"
#include "ip.hpp"
#include "random.hpp"
#include "../external/sha1/sha1.h"
#include "ws_decoder.hpp"
#include "ws_encoder.hpp"

#ifdef ZMQ_HAVE_WINDOWS
#define strcasecmp _stricmp
#endif

//  OSX uses a different name for this socket option
#ifndef IPV6_ADD_MEMBERSHIP
#define IPV6_ADD_MEMBERSHIP IPV6_JOIN_GROUP
#endif

#ifdef __APPLE__
#include <TargetConditionals.h>
#endif

static int
encode_base64 (const unsigned char *in, int in_len, char *out, int out_len);

zmq::ws_engine_t::ws_engine_t (fd_t fd_,
                               const options_t &options_,
                               const endpoint_uri_pair_t &endpoint_uri_pair_,
                               bool client_) :
    stream_engine_base_t (fd_, options_, endpoint_uri_pair_),
    _client (client_),
    _client_handshake_state (client_handshake_initial),
    _server_handshake_state (handshake_initial),
    _header_name_position (0),
    _header_value_position (0),
    _header_upgrade_websocket (false),
    _header_connection_upgrade (false),
    _websocket_protocol (false)
{
    memset (_websocket_key, 0, MAX_HEADER_VALUE_LENGTH + 1);
    memset (_websocket_accept, 0, MAX_HEADER_VALUE_LENGTH + 1);

    _next_msg = static_cast<int (stream_engine_base_t::*) (msg_t *)> (
      &ws_engine_t::routing_id_msg);
    _process_msg = static_cast<int (stream_engine_base_t::*) (msg_t *)> (
      &ws_engine_t::process_routing_id_msg);
}

zmq::ws_engine_t::~ws_engine_t ()
{
}

void zmq::ws_engine_t::plug_internal ()
{
    if (_client) {
        unsigned char nonce[16];
        int *p = (int *) nonce;

        // The nonce doesn't have to be secure one, it is just use to avoid proxy cache
        *p = zmq::generate_random ();
        *(p + 1) = zmq::generate_random ();
        *(p + 2) = zmq::generate_random ();
        *(p + 3) = zmq::generate_random ();

        int size =
          encode_base64 (nonce, 16, _websocket_key, MAX_HEADER_VALUE_LENGTH);
        assert (size > 0);

        size = snprintf (
          (char *) _write_buffer, WS_BUFFER_SIZE,
          "GET / HTTP/1.1\r\n"
          "Host: server.example.com\r\n" // TODO: we need the address here
          "Upgrade: websocket\r\n"
          "Connection: Upgrade\r\n"
          "Sec-WebSocket-Key: %s\r\n"
          "Sec-WebSocket-Protocol: ZWS2.0\r\n"
          "Sec-WebSocket-Version: 13\r\n\r\n",
          _websocket_key);
        assert (size > 0 && size < WS_BUFFER_SIZE);
        _outpos = _write_buffer;
        _outsize = size;
        set_pollout ();
    }

    set_pollin ();
    in_event ();
}

int zmq::ws_engine_t::routing_id_msg (msg_t *msg_)
{
    int rc = msg_->init_size (_options.routing_id_size);
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
        int rc = session ()->push_msg (msg_);
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
    int nbytes = tcp_read (_read_buffer, WS_BUFFER_SIZE);
    if (nbytes == 0) {
        errno = EPIPE;
        error (zmq::i_engine::connection_error);
        return false;
    } else if (nbytes == -1) {
        if (errno != EAGAIN)
            error (zmq::i_engine::connection_error);
        return false;
    }

    _inpos = _read_buffer;
    _insize = nbytes;

    while (_insize > 0) {
        char c = (char) *_inpos;

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
                        _header_name[0] = (char) c;
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
                        strcpy (_websocket_key, _header_value);
                    else if (strcasecmp ("Sec-WebSocket-Protocol", _header_name)
                             == 0)
                        _websocket_protocol =
                          true; // TODO: check if the value is ZWS2.0

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
                        && _websocket_protocol && _websocket_key[0] != '\0') {
                        _server_handshake_state = handshake_complete;

                        const char *magic_string =
                          "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
                        char plain[MAX_HEADER_VALUE_LENGTH + 36 + 1];
                        strcpy (plain, _websocket_key);
                        strcat (plain, magic_string);

                        sha1_ctxt ctx;
                        SHA1_Init (&ctx);
                        SHA1_Update (&ctx, (unsigned char *) _websocket_key,
                                     strlen (_websocket_key));
                        SHA1_Update (&ctx, (unsigned char *) magic_string,
                                     strlen (magic_string));

                        unsigned char hash[SHA_DIGEST_LENGTH];
                        SHA1_Final (hash, &ctx);

                        int accept_key_len = encode_base64 (
                          hash, SHA_DIGEST_LENGTH, _websocket_accept,
                          MAX_HEADER_VALUE_LENGTH);
                        assert (accept_key_len > 0);
                        _websocket_accept[accept_key_len] = '\0';

                        int written =
                          snprintf ((char *) _write_buffer, WS_BUFFER_SIZE,
                                    "HTTP/1.1 101 Switching Protocols\r\n"
                                    "Upgrade: websocket\r\n"
                                    "Connection: Upgrade\r\n"
                                    "Sec-WebSocket-Accept: %s\r\n"
                                    "Sec-WebSocket-Protocol: ZWS2.0\r\n"
                                    "\r\n",
                                    _websocket_accept);
                        assert (written >= 0 && written < WS_BUFFER_SIZE);
                        _outpos = _write_buffer;
                        _outsize = written;

                        _inpos++;
                        _insize--;

                        return true;
                    } else
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
    int nbytes = tcp_read (_read_buffer, WS_BUFFER_SIZE);
    if (nbytes == 0) {
        errno = EPIPE;
        error (zmq::i_engine::connection_error);
        return false;
    } else if (nbytes == -1) {
        if (errno != EAGAIN)
            error (zmq::i_engine::connection_error);
        return false;
    }

    _inpos = _read_buffer;
    _insize = nbytes;

    while (_insize > 0) {
        char c = (char) *_inpos;

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
                        _header_name[0] = (char) c;
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
                        strcpy (_websocket_accept, _header_value);
                    else if (strcasecmp ("Sec-WebSocket-Protocol", _header_name)
                             == 0)
                        _websocket_protocol = true; // TODO: check if ZWS2.0

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
                        && _websocket_protocol
                        && _websocket_accept[0] != '\0') {
                        _client_handshake_state = client_handshake_complete;

                        // TODO: validate accept key

                        _inpos++;
                        _insize--;

                        return true;
                    } else
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

static int
encode_base64 (const unsigned char *in, int in_len, char *out, int out_len)
{
    static const unsigned char base64enc_tab[65] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    int ii, io;
    uint32_t v;
    int rem;

    for (io = 0, ii = 0, v = 0, rem = 0; ii < in_len; ii++) {
        unsigned char ch;
        ch = in[ii];
        v = (v << 8) | ch;
        rem += 8;
        while (rem >= 6) {
            rem -= 6;
            if (io >= out_len)
                return -1; /* truncation is failure */
            out[io++] = base64enc_tab[(v >> rem) & 63];
        }
    }
    if (rem) {
        v <<= (6 - rem);
        if (io >= out_len)
            return -1; /* truncation is failure */
        out[io++] = base64enc_tab[v & 63];
    }
    while (io & 3) {
        if (io >= out_len)
            return -1; /* truncation is failure */
        out[io++] = '=';
    }
    if (io >= out_len)
        return -1; /* no room for null terminator */
    out[io] = 0;
    return io;
}
