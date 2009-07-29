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

#ifndef __ZS_SESSION_HPP_INCLUDED__
#define __ZS_SESSION_HPP_INCLUDED__

#include "i_session.hpp"
#include "safe_object.hpp"
#include "stdint.hpp"
#include "atomic_counter.hpp"

namespace zs
{

    //  Object that encapsulates both mux and demux.

    class session_t : public safe_object_t, public i_session
    {
    public:

        //  Creates the session object.
        session_t (struct object_t *parent_, struct i_thread *thread_,
            struct i_mux *mux_, struct i_demux *demux_,
            bool terminate_on_disconnect_, bool terminate_on_no_pipes_);

        //  i_session implementation
        void set_engine (struct i_engine *engine_);
        void shutdown ();
        bool read (struct zs_msg *msg_);
        bool write (struct zs_msg *msg_);
        void flush ();

        //  Called by the engine when it is being closed.
        void disconnected ();

        //  Creates a message flow between this session and the peer session.
        //  If in_ is true, the messages can flow from the peer to ourselves.
        //  If out_ is true, messages can flow from ourselves to the peer.
        //  It's assumed that peer's seqnum was already incremented.
        void bind (class object_t *peer_, bool in_, bool out_);

        //  Called by mux if new messages are available.
        void revive ();

        //  Functions to set & retrieve index of this MD in thread's array
        //  of session objects.
        void set_index (int index_);
        int get_index ();

    private:

        //  Clean-up.
        ~session_t ();

        //  Terminate is private here. It is called by either when disconnected
        //  or no_pipes event occurs.
        void terminate ();

        void process_bind (class pipe_reader_t *reader_,
            class session_t *peer_);
        void process_reg (class simple_semaphore_t *smph_);
        void process_reg_and_bind (class session_t *peer_,
            bool flow_in_, bool flow_out_);
        void process_engine (i_engine *engine_);

        struct i_mux *mux;
        struct i_demux *demux;

        struct i_thread *thread;
        struct i_engine *engine;

        //  If true termination of the session can be triggered by engine
        //  disconnect/close.
        bool terminate_on_disconnect;

        //  If true termination of the session can be triggered when the last
        //  pipe detaches from it.
        bool terminate_on_no_pipes;

        //  If true, terminate_on_no_pipes should be set when at least one
        //  pipe was bound.
        bool terminate_on_no_pipes_delayed;

        //  Index in thread's session array.
        int index;
    };

}

#endif

