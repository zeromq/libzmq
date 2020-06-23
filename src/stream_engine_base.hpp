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

#ifndef __ZMQ_STREAM_ENGINE_BASE_HPP_INCLUDED__
#define __ZMQ_STREAM_ENGINE_BASE_HPP_INCLUDED__

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
#include "tcp.hpp"

namespace zmq
{
class io_thread_t;
class session_base_t;
class mechanism_t;

//  This engine handles any socket with SOCK_STREAM semantics,
//  e.g. TCP socket or an UNIX domain socket.

class stream_engine_base_t : public io_object_t, public i_engine
{
  public:
    stream_engine_base_t (fd_t fd_,
                          const options_t &options_,
                          const endpoint_uri_pair_t &endpoint_uri_pair_,
                          bool has_handshake_stage_);
    ~stream_engine_base_t () ZMQ_OVERRIDE;

    //  i_engine interface implementation.
    bool has_handshake_stage () ZMQ_FINAL { return _has_handshake_stage; };
    void plug (zmq::io_thread_t *io_thread_,
               zmq::session_base_t *session_) ZMQ_FINAL;
    void terminate () ZMQ_FINAL;
    bool restart_input () ZMQ_FINAL;
    void restart_output () ZMQ_FINAL;
    void zap_msg_available () ZMQ_FINAL;
    const endpoint_uri_pair_t &get_endpoint () const ZMQ_FINAL;

    //  i_poll_events interface implementation.
    void in_event () ZMQ_FINAL;
    void out_event ();
    void timer_event (int id_) ZMQ_FINAL;

  protected:
    typedef metadata_t::dict_t properties_t;
    bool init_properties (properties_t &properties_);

    //  Function to handle network disconnections.
    virtual void error (error_reason_t reason_);

    int next_handshake_command (msg_t *msg_);
    int process_handshake_command (msg_t *msg_);

    int pull_msg_from_session (msg_t *msg_);
    int push_msg_to_session (msg_t *msg_);

    int pull_and_encode (msg_t *msg_);
    virtual int decode_and_push (msg_t *msg_);
    int push_one_then_decode_and_push (msg_t *msg_);

    void set_handshake_timer ();

    virtual bool handshake () { return true; };
    virtual void plug_internal (){};

    virtual int process_command_message (msg_t *msg_) { return -1; };
    virtual int produce_ping_message (msg_t *msg_) { return -1; };
    virtual int process_heartbeat_message (msg_t *msg_) { return -1; };
    virtual int produce_pong_message (msg_t *msg_) { return -1; };

    virtual int read (void *data, size_t size_);
    virtual int write (const void *data_, size_t size_);

    void reset_pollout () { io_object_t::reset_pollout (_handle); }
    void set_pollout () { io_object_t::set_pollout (_handle); }
    void set_pollin () { io_object_t::set_pollin (_handle); }
    session_base_t *session () { return _session; }
    socket_base_t *socket () { return _socket; }

    const options_t _options;

    unsigned char *_inpos;
    size_t _insize;
    i_decoder *_decoder;

    unsigned char *_outpos;
    size_t _outsize;
    i_encoder *_encoder;

    mechanism_t *_mechanism;

    int (stream_engine_base_t::*_next_msg) (msg_t *msg_);
    int (stream_engine_base_t::*_process_msg) (msg_t *msg_);

    //  Metadata to be attached to received messages. May be NULL.
    metadata_t *_metadata;

    //  True iff the engine couldn't consume the last decoded message.
    bool _input_stopped;

    //  True iff the engine doesn't have any message to encode.
    bool _output_stopped;

    //  Representation of the connected endpoints.
    const endpoint_uri_pair_t _endpoint_uri_pair;

    //  ID of the handshake timer
    enum
    {
        handshake_timer_id = 0x40
    };

    //  True is linger timer is running.
    bool _has_handshake_timer;

    //  Heartbeat stuff
    enum
    {
        heartbeat_ivl_timer_id = 0x80,
        heartbeat_timeout_timer_id = 0x81,
        heartbeat_ttl_timer_id = 0x82
    };
    bool _has_ttl_timer;
    bool _has_timeout_timer;
    bool _has_heartbeat_timer;


    const std::string _peer_address;

  private:
    bool in_event_internal ();

    //  Unplug the engine from the session.
    void unplug ();

    int write_credential (msg_t *msg_);

    void mechanism_ready ();

    //  Underlying socket.
    fd_t _s;

    handle_t _handle;

    bool _plugged;

    //  When true, we are still trying to determine whether
    //  the peer is using versioned protocol, and if so, which
    //  version.  When false, normal message flow has started.
    bool _handshaking;

    msg_t _tx_msg;

    bool _io_error;

    //  The session this engine is attached to.
    zmq::session_base_t *_session;

    //  Socket
    zmq::socket_base_t *_socket;

    //  Indicate if engine has an handshake stage, if it does, engine must call session.engine_ready
    //  when handshake is completed.
    bool _has_handshake_stage;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (stream_engine_base_t)
};
}

#endif
