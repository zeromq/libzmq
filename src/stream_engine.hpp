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

#ifndef __ZMQ_STREAM_ENGINE_HPP_INCLUDED__
#define __ZMQ_STREAM_ENGINE_HPP_INCLUDED__

#include <stddef.h>

#include "fd.hpp"
#include "i_engine.hpp"
#include "io_object.hpp"
#include "i_encoder.hpp"
#include "i_decoder.hpp"
#include "options.hpp"
#include "socket_base.hpp"
#include "metadata.hpp"

namespace zmq
{
    //  Protocol revisions
    enum
    {
        ZMTP_1_0 = 0,
        ZMTP_2_0 = 1
    };

    class io_thread_t;
    class msg_t;
    class session_base_t;
    class mechanism_t;

    //  This engine handles any socket with SOCK_STREAM semantics,
    //  e.g. TCP socket or an UNIX domain socket.

    class stream_engine_t : public io_object_t, public i_engine
    {
    public:

        enum error_reason_t {
            protocol_error,
            connection_error,
            timeout_error
        };

        stream_engine_t (fd_t fd_, const options_t &options_,
                         const std::string &endpoint);
        ~stream_engine_t ();

        //  i_engine interface implementation.
        void plug (zmq::io_thread_t *io_thread_,
           zmq::session_base_t *session_);
        void terminate ();
        void restart_input ();
        void restart_output ();
        void zap_msg_available ();

        //  i_poll_events interface implementation.
        void in_event ();
        void out_event ();
        void timer_event (int id_);

    private:
        //  Unplug the engine from the session.
        void unplug ();

        //  Function to handle network disconnections.
        void error (error_reason_t reason);

        //  Receives the greeting message from the peer.
        int receive_greeting ();

        //  Detects the protocol used by the peer.
        bool handshake ();

        int identity_msg (msg_t *msg_);
        int process_identity_msg (msg_t *msg_);

        int next_handshake_command (msg_t *msg);
        int process_handshake_command (msg_t *msg);

        int pull_msg_from_session (msg_t *msg_);
        int push_msg_to_session (msg_t *msg);

        int push_raw_msg_to_session (msg_t *msg);

        int write_credential (msg_t *msg_);
        int pull_and_encode (msg_t *msg_);
        int decode_and_push (msg_t *msg_);
        int push_one_then_decode_and_push (msg_t *msg_);

        void mechanism_ready ();

        size_t add_property (unsigned char *ptr,
            const char *name, const void *value, size_t value_len);

        void set_handshake_timer();

        typedef metadata_t::dict_t properties_t;
        bool init_properties (properties_t & properties);

        int produce_ping_message(msg_t * msg_);
        int process_heartbeat_message(msg_t * msg_);
        int produce_pong_message(msg_t * msg_);

        //  Underlying socket.
        fd_t s;

        //  True iff this is server's engine.
        bool as_server;

        msg_t tx_msg;

        handle_t handle;

        unsigned char *inpos;
        size_t insize;
        i_decoder *decoder;

        unsigned char *outpos;
        size_t outsize;
        i_encoder *encoder;

        //  Metadata to be attached to received messages. May be NULL.
        metadata_t *metadata;

        //  When true, we are still trying to determine whether
        //  the peer is using versioned protocol, and if so, which
        //  version.  When false, normal message flow has started.
        bool handshaking;

        static const size_t signature_size = 10;

        //  Size of ZMTP/1.0 and ZMTP/2.0 greeting message
        static const size_t v2_greeting_size = 12;

        //  Size of ZMTP/3.0 greeting message
        static const size_t v3_greeting_size = 64;

        //  Expected greeting size.
        size_t greeting_size;

        //  Greeting received from, and sent to peer
        unsigned char greeting_recv [v3_greeting_size];
        unsigned char greeting_send [v3_greeting_size];

        //  Size of greeting received so far
        unsigned int greeting_bytes_read;

        //  The session this engine is attached to.
        zmq::session_base_t *session;

        options_t options;

        // String representation of endpoint
        std::string endpoint;

        bool plugged;

        int (stream_engine_t::*next_msg) (msg_t *msg_);

        int (stream_engine_t::*process_msg) (msg_t *msg_);

        bool io_error;

        //  Indicates whether the engine is to inject a phantom
        //  subscription message into the incoming stream.
        //  Needed to support old peers.
        bool subscription_required;

        mechanism_t *mechanism;

        //  True iff the engine couldn't consume the last decoded message.
        bool input_stopped;

        //  True iff the engine doesn't have any message to encode.
        bool output_stopped;

        //  ID of the handshake timer
        enum {handshake_timer_id = 0x40};

        //  True is linger timer is running.
        bool has_handshake_timer;

        //  Heartbeat stuff
        enum {
            heartbeat_ivl_timer_id = 0x80,
            heartbeat_timeout_timer_id = 0x81,
            heartbeat_ttl_timer_id = 0x82
        };
        bool has_ttl_timer;
        bool has_timeout_timer;
        bool has_heartbeat_timer;
        int heartbeat_timeout;

        // Socket
        zmq::socket_base_t *socket;

        std::string peer_address;

        stream_engine_t (const stream_engine_t&);
        const stream_engine_t &operator = (const stream_engine_t&);
    };

}

#endif
