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

#ifndef __ZMQ_SESSION_HPP_INCLUDED__
#define __ZMQ_SESSION_HPP_INCLUDED__

#include <string>

#include "i_inout.hpp"
#include "i_endpoint.hpp"
#include "owned.hpp"
#include "options.hpp"

namespace zmq
{

    class session_t : public owned_t, public i_inout, public i_endpoint
    {
    public:

        session_t (object_t *parent_, socket_base_t *owner_, const char *name_,
            const options_t &options_, bool reconnect_);

        //  i_inout interface implementation.
        bool read (::zmq_msg_t *msg_);
        bool write (::zmq_msg_t *msg_);
        void flush ();
        void detach ();

        //  i_endpoint interface implementation.
        void attach_pipes (class reader_t *inpipe_, class writer_t *outpipe_);
        void detach_inpipe (class reader_t *pipe_);
        void detach_outpipe (class writer_t *pipe_);
        void kill (class reader_t *pipe_);
        void revive (class reader_t *pipe_);

    private:

        ~session_t ();

        //  Handlers for incoming commands.
        void process_plug ();
        void process_unplug ();
        void process_attach (struct i_engine *engine_);

        //  Inbound pipe, i.e. one the session is getting messages from.
        class reader_t *in_pipe;

        //  If true, in_pipe is active. Otherwise there are no messages to get.
        bool active;

        //  Outbound pipe, i.e. one the socket is sending messages to.
        class writer_t *out_pipe;

        struct i_engine *engine;

        //  The name of the session. One that is used to register it with
        //  socket-level repository of sessions.
        std::string name;

        //  Inherited socket options.
        options_t options;

        //  If true, reconnection is required after connection breaks.
        bool reconnect;

        session_t (const session_t&);
        void operator = (const session_t&);
    };

}

#endif
