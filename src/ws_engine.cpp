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
    _client (client_),
    _plugged (false),
    _socket (NULL),
    _fd (fd_),
    _session (NULL),
    _handle (static_cast<handle_t> (NULL)),
    _options (options_),
    _endpoint_uri_pair (endpoint_uri_pair_),
    _handshaking (true),
    _client_handshake_state (client_handshake_initial),
    _server_handshake_state (handshake_initial),
    _header_name_position (0),
    _header_value_position (0),
    _header_upgrade_websocket (false),
    _header_connection_upgrade (false),
    _websocket_protocol (false),
    _input_stopped (false),
    _decoder (NULL),
    _inpos (NULL),
    _insize (0),
    _output_stopped (false),
    _outpos (NULL),
    _outsize (0),
    _encoder (NULL),
    _sent_routing_id (false),
    _received_routing_id (false)
{
    //  Put the socket into non-blocking mode.
    unblock_socket (_fd);

    memset (_websocket_key, 0, MAX_HEADER_VALUE_LENGTH + 1);
    memset (_websocket_accept, 0, MAX_HEADER_VALUE_LENGTH + 1);

    int rc = _tx_msg.init ();
    errno_assert (rc == 0);
}

zmq::ws_engine_t::~ws_engine_t ()
{
    zmq_assert (!_plugged);

    if (_fd != retired_fd) {
#ifdef ZMQ_HAVE_WINDOWS
        int rc = closesocket (_fd);
        wsa_assert (rc != SOCKET_ERROR);
#else
        int rc = close (_fd);
        errno_assert (rc == 0);
#endif
        _fd = retired_fd;
    }

    int rc = _tx_msg.close ();
    errno_assert (rc == 0);

    LIBZMQ_DELETE (_encoder);
    LIBZMQ_DELETE (_decoder);
}

void zmq::ws_engine_t::plug (io_thread_t *io_thread_, session_base_t *session_)
{
    zmq_assert (!_plugged);
    _plugged = true;

    zmq_assert (!_session);
    zmq_assert (session_);
    _session = session_;
    _socket = _session->get_socket ();

    //  Connect to I/O threads poller object.
    io_object_t::plug (io_thread_);
    _handle = add_fd (_fd);

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
        _output_stopped = false;
        set_pollout (_handle);
    } else
        _output_stopped = true;

    _input_stopped = false;
    set_pollin (_handle);
    in_event ();
}


void zmq::ws_engine_t::unplug ()
{
    zmq_assert (_plugged);
    _plugged = false;

    rm_fd (_handle);

    //  Disconnect from I/O threads poller object.
    io_object_t::unplug ();
}


void zmq::ws_engine_t::terminate ()
{
    unplug ();
    delete this;
}

void zmq::ws_engine_t::in_event ()
{
    if (_handshaking) {
        if (_client) {
            if (!client_handshake ())
                return;
        } else if (!server_handshake ())
            return;
    }

    zmq_assert (_decoder);

    //  If there's no data to process in the buffer...
    if (_insize == 0) {
        //  Retrieve the buffer and read as much data as possible.
        //  Note that buffer can be arbitrarily large. However, we assume
        //  the underlying TCP layer has fixed buffer size and thus the
        //  number of bytes read will be always limited.
        size_t bufsize = 0;
        _decoder->get_buffer (&_inpos, &bufsize);

        const int rc = tcp_read (_fd, _inpos, bufsize);

        if (rc == 0) {
            // connection closed by peer
            errno = EPIPE;
            error (zmq::stream_engine_t::connection_error);
            return;
        }
        if (rc == -1) {
            if (errno != EAGAIN) {
                error (zmq::stream_engine_t::connection_error);
                return;
            }
            return;
        }

        //  Adjust input size
        _insize = static_cast<size_t> (rc);
        // Adjust buffer size to received bytes
        _decoder->resize_buffer (_insize);
    }

    int rc = 0;
    size_t processed = 0;

    while (_insize > 0) {
        rc = _decoder->decode (_inpos, _insize, processed);
        zmq_assert (processed <= _insize);
        _inpos += processed;
        _insize -= processed;
        if (rc == 0 || rc == -1)
            break;

        if (!_received_routing_id) {
            _received_routing_id = true;
            if (_options.recv_routing_id)
                _decoder->msg ()->set_flags (msg_t::routing_id);
            else {
                _decoder->msg ()->close ();
                _decoder->msg ()->init ();
                continue;
            }
        }

        rc = _session->push_msg (_decoder->msg ());
        if (rc == -1)
            break;
    }

    //  Tear down the connection if we have failed to decode input data
    //  or the session has rejected the message.
    if (rc == -1) {
        if (errno != EAGAIN) {
            error (zmq::stream_engine_t::protocol_error);
            return;
        }
        _input_stopped = true;
        reset_pollin (_handle);
    }

    _session->flush ();
    return;
}

void zmq::ws_engine_t::out_event ()
{
    //  If write buffer is empty, try to read new data from the encoder.
    if (!_outsize) {
        //  Even when we stop polling as soon as there is no
        //  data to send, the poller may invoke out_event one
        //  more time due to 'speculative write' optimisation.
        if (unlikely (_encoder == NULL)) {
            zmq_assert (_handshaking);
            return;
        }

        _outpos = NULL;
        _outsize = _encoder->encode (&_outpos, 0);

        while (_outsize < static_cast<size_t> (_options.out_batch_size)) {
            if (!_sent_routing_id) {
                _tx_msg.close ();
                int rc = _tx_msg.init_size (_options.routing_id_size);
                errno_assert (rc == 0);
                if (_options.routing_id_size > 0)
                    memcpy (_tx_msg.data (), _options.routing_id,
                            _options.routing_id_size);
                _sent_routing_id = true;
            } else if (_session->pull_msg (&_tx_msg) == -1)
                break;
            _encoder->load_msg (&_tx_msg);
            unsigned char *bufptr = _outpos + _outsize;
            size_t n =
              _encoder->encode (&bufptr, _options.out_batch_size - _outsize);
            zmq_assert (n > 0);
            if (_outpos == NULL)
                _outpos = bufptr;
            _outsize += n;
        }

        //  If there is no data to send, stop polling for output.
        if (_outsize == 0) {
            _output_stopped = true;
            reset_pollout (_handle);
            return;
        }
    }

    //  If there are any data to write in write buffer, write as much as
    //  possible to the socket. Note that amount of data to write can be
    //  arbitrarily large. However, we assume that underlying TCP layer has
    //  limited transmission buffer and thus the actual number of bytes
    //  written should be reasonably modest.
    const int nbytes = tcp_write (_fd, _outpos, _outsize);

    //  IO error has occurred. We stop waiting for output events.
    //  The engine is not terminated until we detect input error;
    //  this is necessary to prevent losing incoming messages.
    if (nbytes == -1) {
        _output_stopped = true;
        reset_pollout (_handle);
        return;
    }

    _outpos += nbytes;
    _outsize -= nbytes;

    //  If we are still handshaking and there are no data
    //  to send, stop polling for output.
    if (unlikely (_handshaking))
        if (_outsize == 0) {
            _output_stopped = true;
            reset_pollout (_handle);
        }
}

const zmq::endpoint_uri_pair_t &zmq::ws_engine_t::get_endpoint () const
{
    return _endpoint_uri_pair;
}

void zmq::ws_engine_t::restart_output ()
{
    if (likely (_output_stopped)) {
        set_pollout (_handle);
        _output_stopped = false;
    }
}

bool zmq::ws_engine_t::server_handshake ()
{
    int nbytes = tcp_read (_fd, _read_buffer, WS_BUFFER_SIZE);
    if (nbytes == 0) {
        errno = EPIPE;
        error (zmq::stream_engine_t::connection_error);
        return false;
    } else if (nbytes == -1) {
        if (errno != EAGAIN)
            error (zmq::stream_engine_t::connection_error);
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
                        _handshaking = false;

                        // TODO: check which decoder/encoder to use according to selected protocol
                        _encoder = new (std::nothrow)
                          ws_encoder_t (_options.out_batch_size, false);
                        alloc_assert (_encoder);

                        _decoder = new (std::nothrow) ws_decoder_t (
                          _options.in_batch_size, _options.maxmsgsize,
                          _options.zero_copy, true);
                        alloc_assert (_decoder);

                        _socket->event_handshake_succeeded (_endpoint_uri_pair,
                                                            0);

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

                        if (_output_stopped)
                            restart_output ();
                    } else
                        _server_handshake_state = handshake_error;
                } else
                    _server_handshake_state = handshake_error;
                break;
            case handshake_complete:
                // no more bytes are allowed after complete
                _server_handshake_state = handshake_error;
            default:
                assert (false);
        }

        _inpos++;
        _insize--;

        if (_server_handshake_state == handshake_error) {
            // TODO: send bad request

            _socket->event_handshake_failed_protocol (
              _endpoint_uri_pair, ZMQ_PROTOCOL_ERROR_WS_UNSPECIFIED);

            error (zmq::stream_engine_t::protocol_error);
            return false;
        }
    }
    return _server_handshake_state == handshake_complete;
}

bool zmq::ws_engine_t::client_handshake ()
{
    int nbytes = tcp_read (_fd, _read_buffer, WS_BUFFER_SIZE);
    if (nbytes == 0) {
        errno = EPIPE;
        error (zmq::stream_engine_t::connection_error);
        return false;
    } else if (nbytes == -1) {
        if (errno != EAGAIN)
            error (zmq::stream_engine_t::connection_error);
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
                        _handshaking = false;

                        _encoder = new (std::nothrow)
                          ws_encoder_t (_options.out_batch_size, true);
                        alloc_assert (_encoder);

                        _decoder = new (std::nothrow) ws_decoder_t (
                          _options.in_batch_size, _options.maxmsgsize,
                          _options.zero_copy, false);
                        alloc_assert (_decoder);

                        _socket->event_handshake_succeeded (_endpoint_uri_pair,
                                                            0);

                        // TODO: validate accept key

                        if (_output_stopped)
                            restart_output ();

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
            _socket->event_handshake_failed_protocol (
              _endpoint_uri_pair, ZMQ_PROTOCOL_ERROR_WS_UNSPECIFIED);

            error (zmq::stream_engine_t::protocol_error);
            return false;
        }
    }

    return false;
}

void zmq::ws_engine_t::error (zmq::stream_engine_t::error_reason_t reason_)
{
    zmq_assert (_session);

    if (reason_ != zmq::stream_engine_t::protocol_error && _handshaking) {
        int err = errno;
        _socket->event_handshake_failed_no_detail (_endpoint_uri_pair, err);
    }

    _socket->event_disconnected (_endpoint_uri_pair, _fd);
    _session->flush ();
    _session->engine_error (reason_);
    unplug ();
    delete this;
}

bool zmq::ws_engine_t::restart_input ()
{
    zmq_assert (_input_stopped);

    _input_stopped = false;
    set_pollin (_handle);
    in_event ();

    return true;
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
