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

#ifndef __ZMQ_WS_ENGINE_HPP_INCLUDED__
#define __ZMQ_WS_ENGINE_HPP_INCLUDED__

#include "io_object.hpp"
#include "address.hpp"
#include "msg.hpp"
#include "stream_engine_base.hpp"
#include "ws_address.hpp"

#define WS_BUFFER_SIZE 8192
#define MAX_HEADER_NAME_LENGTH 1024
#define MAX_HEADER_VALUE_LENGTH 2048

namespace zmq
{
class io_thread_t;
class session_base_t;

typedef enum
{
    handshake_initial = 0,
    request_line_G,
    request_line_GE,
    request_line_GET,
    request_line_GET_space,
    request_line_resource,
    request_line_resource_space,
    request_line_H,
    request_line_HT,
    request_line_HTT,
    request_line_HTTP,
    request_line_HTTP_slash,
    request_line_HTTP_slash_1,
    request_line_HTTP_slash_1_dot,
    request_line_HTTP_slash_1_dot_1,
    request_line_cr,
    header_field_begin_name,
    header_field_name,
    header_field_colon,
    header_field_value_trailing_space,
    header_field_value,
    header_field_cr,
    handshake_end_line_cr,
    handshake_complete,

    handshake_error = -1
} ws_server_handshake_state_t;


typedef enum
{
    client_handshake_initial = 0,
    response_line_H,
    response_line_HT,
    response_line_HTT,
    response_line_HTTP,
    response_line_HTTP_slash,
    response_line_HTTP_slash_1,
    response_line_HTTP_slash_1_dot,
    response_line_HTTP_slash_1_dot_1,
    response_line_HTTP_slash_1_dot_1_space,
    response_line_status_1,
    response_line_status_10,
    response_line_status_101,
    response_line_status_101_space,
    response_line_s,
    response_line_sw,
    response_line_swi,
    response_line_swit,
    response_line_switc,
    response_line_switch,
    response_line_switchi,
    response_line_switchin,
    response_line_switching,
    response_line_switching_space,
    response_line_p,
    response_line_pr,
    response_line_pro,
    response_line_prot,
    response_line_proto,
    response_line_protoc,
    response_line_protoco,
    response_line_protocol,
    response_line_protocols,
    response_line_cr,
    client_header_field_begin_name,
    client_header_field_name,
    client_header_field_colon,
    client_header_field_value_trailing_space,
    client_header_field_value,
    client_header_field_cr,
    client_handshake_end_line_cr,
    client_handshake_complete,

    client_handshake_error = -1
} ws_client_handshake_state_t;

class ws_engine_t : public stream_engine_base_t
{
  public:
    ws_engine_t (fd_t fd_,
                 const options_t &options_,
                 const endpoint_uri_pair_t &endpoint_uri_pair_,
                 const ws_address_t &address_,
                 bool client_);
    ~ws_engine_t ();

  protected:
    int decode_and_push (msg_t *msg_);
    int process_command_message (msg_t *msg_);
    int produce_pong_message (msg_t *msg_);
    int produce_ping_message (msg_t *msg_);
    bool handshake ();
    void plug_internal ();
    void start_ws_handshake ();

  private:
    int routing_id_msg (msg_t *msg_);
    int process_routing_id_msg (msg_t *msg_);
    int produce_close_message (msg_t *msg_);
    int produce_no_msg_after_close (msg_t *msg_);
    int close_connection_after_close (msg_t *msg_);

    bool select_protocol (const char *protocol);

    bool client_handshake ();
    bool server_handshake ();

    bool _client;
    ws_address_t _address;

    ws_client_handshake_state_t _client_handshake_state;
    ws_server_handshake_state_t _server_handshake_state;

    unsigned char _read_buffer[WS_BUFFER_SIZE];
    unsigned char _write_buffer[WS_BUFFER_SIZE];
    char _header_name[MAX_HEADER_NAME_LENGTH + 1];
    int _header_name_position;
    char _header_value[MAX_HEADER_VALUE_LENGTH + 1];
    int _header_value_position;

    bool _header_upgrade_websocket;
    bool _header_connection_upgrade;
    char _websocket_protocol[256];
    char _websocket_key[MAX_HEADER_VALUE_LENGTH + 1];
    char _websocket_accept[MAX_HEADER_VALUE_LENGTH + 1];

    int _heartbeat_timeout;
    msg_t _close_msg;
};
}

#endif
