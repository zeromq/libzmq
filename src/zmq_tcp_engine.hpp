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

#ifndef __ZMQ_ZMQ_TCP_ENGINE_HPP_INCLUDED__
#define __ZMQ_ZMQ_TCP_ENGINE_HPP_INCLUDED__

#include "i_engine.hpp"
#include "i_poller.hpp"
#include "i_poll_events.hpp"
#include "fd.hpp"
#include "tcp_socket.hpp"
#include "zmq_encoder.hpp"
#include "zmq_decoder.hpp"

namespace zmq
{

    class zmq_tcp_engine_t : public i_engine, public i_poll_events
    {
    public:

        zmq_tcp_engine_t (fd_t fd_);

        //  i_engine implementation.
        void attach (struct i_poller *poller_, struct i_session *session_);
        void detach ();
        void revive ();
        void schedule_terminate ();
        void terminate ();
        void shutdown ();

        //  i_poll_events implementation.
        void in_event ();
        void out_event ();
        void timer_event ();

    private:

        void error ();

        //  Clean-up.
        ~zmq_tcp_engine_t ();

        //  The underlying TCP socket.
        tcp_socket_t socket;

        //  Handle associated with the socket.
        handle_t handle;

        //  I/O thread that the engine runs in.
        i_poller *poller;

        //  Reference to the associated session object.
        i_session *session;

        //  If true, engine should terminate itself as soon as possible.
        bool terminating;

        unsigned char *inbuf;
        int insize;
        int inpos;

        unsigned char *outbuf;
        int outsize;
        int outpos;

        zmq_encoder_t encoder;
        zmq_decoder_t decoder;

        zmq_tcp_engine_t (const zmq_tcp_engine_t&);
        void operator = (const zmq_tcp_engine_t&);
    };

}

#endif
