/*
    Copyright (c) 2007-2009 FastMQ Inc.

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the Lesser GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    Lesser GNU General Public License for more details.

    You should have received a copy of the Lesser GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __ZMQ_ZMQ_ENGINE_HPP_INCLUDED__
#define __ZMQ_ZMQ_ENGINE_HPP_INCLUDED__

#include "io_object.hpp"
#include "tcp_socket.hpp"
#include "zmq_encoder.hpp"
#include "zmq_decoder.hpp"

namespace zmq
{

    class zmq_engine_t : public io_object_t
    {
    public:

        zmq_engine_t (class io_thread_t *parent_, fd_t fd_);
        ~zmq_engine_t ();

        void plug (struct i_inout *inout_);
        void unplug ();

        //  i_poll_events interface implementation.
        void in_event ();
        void out_event ();

    private:

        //  Function to handle network disconnections.
        void error ();

        tcp_socket_t tcp_socket;
        handle_t handle;

        unsigned char *inbuf;
        int insize;
        int inpos;

        unsigned char *outbuf;
        int outsize;
        int outpos;

        i_inout *inout;

        zmq_encoder_t encoder;
        zmq_decoder_t decoder;

        zmq_engine_t (const zmq_engine_t&);
        void operator = (const zmq_engine_t&);
    };

}

#endif
