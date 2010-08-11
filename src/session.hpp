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

#ifndef __ZMQ_SESSION_HPP_INCLUDED__
#define __ZMQ_SESSION_HPP_INCLUDED__

#include "own.hpp"
#include "i_inout.hpp"
#include "options.hpp"
#include "blob.hpp"
#include "pipe.hpp"

namespace zmq
{

    class session_t :
        public own_t,
        public i_inout,
        public i_reader_events,
        public i_writer_events
    {
    public:

        session_t (class io_thread_t *io_thread_,
            class socket_base_t *socket_, const options_t &options_);

        //  i_inout interface implementation. Note that detach method is not
        //  implemented by generic session. Different session types may handle
        //  engine disconnection in different ways.
        bool read (::zmq_msg_t *msg_);
        bool write (::zmq_msg_t *msg_);
        void flush ();
        void detach ();

        void attach_pipes (class reader_t *inpipe_, class writer_t *outpipe_,
            const blob_t &peer_identity_);

        //  i_reader_events interface implementation.
        void activated (class reader_t *pipe_);
        void terminated (class reader_t *pipe_);

        //  i_writer_events interface implementation.
        void activated (class writer_t *pipe_);
        void terminated (class writer_t *pipe_);

    protected:

        //  Forcefully close this session (without sending
        //  outbound messages to the wire).
        void terminate ();

        //  Two events for the derived session type. Attached is triggered
        //  when session is attached to a peer, detached is triggered at the
        //  beginning of the termination process when session is about to
        //  be detached from the peer.
        virtual void attached (const blob_t &peer_identity_);
        virtual void detached ();

        ~session_t ();

        //  Remove any half processed messages. Flush unflushed messages.
        //  Call this function when engine disconnect to get rid of leftovers.
        void clean_pipes ();

        //  Inherited socket options. These are visible to all session classes.
        options_t options;

    private:

        //  Handlers for incoming commands.
        void process_plug ();
        void process_unplug ();
        void process_attach (struct i_engine *engine_,
            const blob_t &peer_identity_);
        void process_term ();

        //  Check whether object is ready for termination. If so proceed
        //  with closing child objects.
        void finalise ();

        //  Inbound pipe, i.e. one the session is getting messages from.
        class reader_t *in_pipe;

        //  This flag is true if the remainder of the message being processed
        //  is still in the in pipe.
        bool incomplete_in;

        //  If true, in_pipe is active. Otherwise there are no messages to get.
        bool active;

        //  Outbound pipe, i.e. one the socket is sending messages to.
        class writer_t *out_pipe;

        //  The protocol I/O engine connected to the session.
        struct i_engine *engine;

        //  Identity of the peer (say the component on the other side
        //  of TCP connection).
        blob_t peer_identity;

        //  The socket the session belongs to.
        class socket_base_t *socket;

        //  I/O thread the session is living in. It will be used to plug in
        //  the engines into the same thread.
        class io_thread_t *io_thread;

        //  True if pipes were already attached.
        bool attach_processed;

        //  True if term command was already processed.
        bool term_processed;

        session_t (const session_t&);
        void operator = (const session_t&);
    };

}

#endif
