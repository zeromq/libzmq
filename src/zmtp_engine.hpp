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

#ifndef __ZMQ_ZMTP_ENGINE_HPP_INCLUDED__
#define __ZMQ_ZMTP_ENGINE_HPP_INCLUDED__

#include <stddef.h>

#include "fd.hpp"
#include "i_engine.hpp"
#include "io_object.hpp"
#include "i_encoder.hpp"
#include "i_decoder.hpp"
#include "options.hpp"
#include "socket_base.hpp"
#include "metadata.hpp"
#include "msg.hpp"
#include "stream_engine_base.hpp"

namespace zmq
{
//  Protocol revisions
enum
{
    ZMTP_1_0 = 0,
    ZMTP_2_0 = 1,
    ZMTP_3_x = 3
};

class io_thread_t;
class session_base_t;
class mechanism_t;

//  This engine handles any socket with SOCK_STREAM semantics,
//  e.g. TCP socket or an UNIX domain socket.

class zmtp_engine_t ZMQ_FINAL : public stream_engine_base_t
{
  public:
    zmtp_engine_t (fd_t fd_,
                   const options_t &options_,
                   const endpoint_uri_pair_t &endpoint_uri_pair_);
    ~zmtp_engine_t ();

  protected:
    //  Detects the protocol used by the peer.
    bool handshake ();

    void plug_internal ();

    int process_command_message (msg_t *msg_);
    int produce_ping_message (msg_t *msg_);
    int process_heartbeat_message (msg_t *msg_);
    int produce_pong_message (msg_t *msg_);

  private:
    //  Receive the greeting from the peer.
    int receive_greeting ();
    void receive_greeting_versioned ();

    typedef bool (zmtp_engine_t::*handshake_fun_t) ();
    static handshake_fun_t select_handshake_fun (bool unversioned,
                                                 unsigned char revision,
                                                 unsigned char minor);

    bool handshake_v1_0_unversioned ();
    bool handshake_v1_0 ();
    bool handshake_v2_0 ();
    bool handshake_v3_x (bool downgrade_sub);
    bool handshake_v3_0 ();
    bool handshake_v3_1 ();

    int routing_id_msg (msg_t *msg_);
    int process_routing_id_msg (msg_t *msg_);

    msg_t _routing_id_msg;

    //  Need to store PING payload for PONG
    msg_t _pong_msg;

    static const size_t signature_size = 10;

    //  Size of ZMTP/1.0 and ZMTP/2.0 greeting message
    static const size_t v2_greeting_size = 12;

    //  Size of ZMTP/3.0 greeting message
    static const size_t v3_greeting_size = 64;

    //  Expected greeting size.
    size_t _greeting_size;

    //  Greeting received from, and sent to peer
    unsigned char _greeting_recv[v3_greeting_size];
    unsigned char _greeting_send[v3_greeting_size];

    //  Size of greeting received so far
    unsigned int _greeting_bytes_read;

    //  Indicates whether the engine is to inject a phantom
    //  subscription message into the incoming stream.
    //  Needed to support old peers.
    bool _subscription_required;

    int _heartbeat_timeout;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (zmtp_engine_t)
};
}

#endif
