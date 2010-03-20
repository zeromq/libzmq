/*
    Copyright (c) 2007-2010 iMatix Corporation

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

#include <stddef.h>

#include <string>

#include "i_engine.hpp"
#include "io_object.hpp"
#include "tcp_socket.hpp"
#include "zmq_encoder.hpp"
#include "zmq_decoder.hpp"
#include "options.hpp"

namespace zmq
{

    class zmq_engine_t : public io_object_t, public i_engine
    {
    public:

        zmq_engine_t (class io_thread_t *parent_, fd_t fd_,
            const options_t &options_, bool reconnect_, 
            const char *protocol_, const char *address_);
        ~zmq_engine_t ();

        //  i_engine interface implementation.
        void plug (struct i_inout *inout_);
        void unplug ();
        void revive ();
        void resume_input ();

        //  i_poll_events interface implementation.
        void in_event ();
        void out_event ();

    private:

        //  Function to handle network disconnections.
        void error ();

        tcp_socket_t tcp_socket;
        handle_t handle;

        unsigned char *inpos;
        size_t insize;
        zmq_decoder_t decoder;

        unsigned char *outpos;
        size_t outsize;
        zmq_encoder_t encoder;

        i_inout *inout;

        options_t options;

        bool reconnect;
        std::string protocol;
        std::string address;

        zmq_engine_t (const zmq_engine_t&);
        void operator = (const zmq_engine_t&);
    };

}

#endif
