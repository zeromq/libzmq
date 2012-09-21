/*
    Copyright (c) 2009-2011 250bpm s.r.o.
    Copyright (c) 2007-2009 iMatix Corporation
    Copyright (c) 2011 VMware, Inc.
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

#ifndef __ZMQ_SESSION_BASE_HPP_INCLUDED__
#define __ZMQ_SESSION_BASE_HPP_INCLUDED__

#include <string>
#include <stdarg.h>

#include "own.hpp"
#include "io_object.hpp"
#include "pipe.hpp"
#include "i_msg_source.hpp"
#include "i_msg_sink.hpp"
#include "socket_base.hpp"

namespace zmq
{

    class pipe_t;
    class io_thread_t;
    class socket_base_t;
    struct i_engine;
    struct address_t;

    class session_base_t :
        public own_t,
        public io_object_t,
        public i_pipe_events,
        public i_msg_source,
        public i_msg_sink
    {
    public:

        //  Create a session of the particular type.
        static session_base_t *create (zmq::io_thread_t *io_thread_,
            bool connect_, zmq::socket_base_t *socket_,
            const options_t &options_, const address_t *addr_);

        //  To be used once only, when creating the session.
        void attach_pipe (zmq::pipe_t *pipe_);

        //  i_msg_source interface implementation.
        virtual int pull_msg (msg_t *msg_);

        //  i_msg_sink interface implementation.
        virtual int push_msg (msg_t *msg_);

        //  Following functions are the interface exposed towards the engine.
        virtual void reset ();
        void flush ();
        void detach ();

        //  i_pipe_events interface implementation.
        void read_activated (zmq::pipe_t *pipe_);
        void write_activated (zmq::pipe_t *pipe_);
        void hiccuped (zmq::pipe_t *pipe_);
        void terminated (zmq::pipe_t *pipe_);

        socket_base_t *get_socket ();

    protected:

        session_base_t (zmq::io_thread_t *io_thread_, bool connect_,
            zmq::socket_base_t *socket_, const options_t &options_,
            const address_t *addr_);
        virtual ~session_base_t ();

    private:

        void start_connecting (bool wait_);

        void detached ();

        //  Handlers for incoming commands.
        void process_plug ();
        void process_attach (zmq::i_engine *engine_);
        void process_term (int linger_);

        //  i_poll_events handlers.
        void timer_event (int id_);

        //  Remove any half processed messages. Flush unflushed messages.
        //  Call this function when engine disconnect to get rid of leftovers.
        void clean_pipes ();

        //  Call this function to move on with the delayed process_term.
        void proceed_with_term ();

        //  If true, this session (re)connects to the peer. Otherwise, it's
        //  a transient session created by the listener.
        bool connect;

        //  Pipe connecting the session to its socket.
        zmq::pipe_t *pipe;
        
        //  This set is added to with pipes we are disconnecting, but haven't yet completed
        std::set<pipe_t *> terminating_pipes;

        //  This flag is true if the remainder of the message being processed
        //  is still in the in pipe.
        bool incomplete_in;

        //  True if termination have been suspended to push the pending
        //  messages to the network.
        bool pending;

        //  The protocol I/O engine connected to the session.
        zmq::i_engine *engine;

        //  The socket the session belongs to.
        zmq::socket_base_t *socket;

        //  I/O thread the session is living in. It will be used to plug in
        //  the engines into the same thread.
        zmq::io_thread_t *io_thread;

        //  ID of the linger timer
        enum {linger_timer_id = 0x20};

        //  True is linger timer is running.
        bool has_linger_timer;

        //  If true, identity has been sent/received from the network.
        bool identity_sent;
        bool identity_received;

        //  Protocol and address to use when connecting.
        const address_t *addr;

        session_base_t (const session_base_t&);
        const session_base_t &operator = (const session_base_t&);
    };

}

#endif
