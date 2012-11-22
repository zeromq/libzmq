/*
    Copyright (c) 2009-2011 250bpm s.r.o.
    Copyright (c) 2007-2009 iMatix Corporation
    Copyright (c) 2007-2011 Other contributors as noted in the AUTHORS file

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __ZMQ_STREAM_ENGINE_HPP_INCLUDED__
#define __ZMQ_STREAM_ENGINE_HPP_INCLUDED__

#include <stddef.h>

#include "fd.hpp"
#include "i_engine.hpp"
#include "i_msg_sink.hpp"
#include "io_object.hpp"
#include "i_encoder.hpp"
#include "i_decoder.hpp"
#include "options.hpp"
#include "socket_base.hpp"
#include "../include/zmq.h"

namespace zmq
{

    class io_thread_t;
    class session_base_t;

    //  This engine handles any socket with SOCK_STREAM semantics,
    //  e.g. TCP socket or an UNIX domain socket.

    class stream_engine_t : public io_object_t, public i_engine, public i_msg_sink
    {
    public:

        stream_engine_t (fd_t fd_, const options_t &options_, const std::string &endpoint);
        ~stream_engine_t ();

        //  i_engine interface implementation.
        void plug (zmq::io_thread_t *io_thread_,
           zmq::session_base_t *session_);
        void terminate ();
        void activate_in ();
        void activate_out ();

        //  i_msg_sink interface implementation.
        virtual int push_msg (msg_t *msg_);

        //  i_poll_events interface implementation.
        void in_event ();
        void out_event ();

    private:

        //  Unplug the engine from the session.
        void unplug ();

        //  Function to handle network disconnections.
        void error ();

        //  Receives the greeting message from the peer.
        int receive_greeting ();

        //  Detects the protocol used by the peer.
        bool handshake ();

        //  Writes data to the socket. Returns the number of bytes actually
        //  written (even zero is to be considered to be a success). In case
        //  of error or orderly shutdown by the other peer -1 is returned.
        int write (const void *data_, size_t size_);

        //  Reads data from the socket (up to 'size' bytes). Returns the number
        //  of bytes actually read (even zero is to be considered to be
        //  a success). In case of error or orderly shutdown by the other
        //  peer -1 is returned.
        int read (void *data_, size_t size_);

        //  Underlying socket.
        fd_t s;

        //  Size of the greeting message:
        //  Preamble (10 bytes) + version (1 byte) + socket type (1 byte).
        const static size_t greeting_size = 12;

        //  True iff we are registered with an I/O poller.
        bool io_enabled;

        handle_t handle;

        unsigned char *inpos;
        size_t insize;
        i_decoder *decoder;

        unsigned char *outpos;
        size_t outsize;
        i_encoder *encoder;

        //  When true, we are still trying to determine whether
        //  the peer is using versioned protocol, and if so, which
        //  version.  When false, normal message flow has started.
        bool handshaking;

        //  The receive buffer holding the greeting message
        //  that we are receiving from the peer.
        unsigned char greeting [greeting_size];

        //  The number of bytes of the greeting message that
        //  we have already received.
        unsigned int greeting_bytes_read;

        //  The send buffer holding the greeting message
        //  that we are sending to the peer.
        unsigned char greeting_output_buffer [greeting_size];

        //  The session this engine is attached to.
        zmq::session_base_t *session;

        options_t options;

        // String representation of endpoint
        std::string endpoint;

        bool plugged;

        // Socket
        zmq::socket_base_t *socket;

        stream_engine_t (const stream_engine_t&);
        const stream_engine_t &operator = (const stream_engine_t&);
    };

}

#endif
