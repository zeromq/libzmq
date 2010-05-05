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

#ifndef __ZMQ_OBJECT_HPP_INCLUDED__
#define __ZMQ_OBJECT_HPP_INCLUDED__

#include "stdint.hpp"
#include "blob.hpp"

namespace zmq
{
    //  Base class for all objects that participate in inter-thread
    //  communication.

    class object_t
    {
    public:

        object_t (class ctx_t *ctx_, uint32_t thread_slot_);
        object_t (object_t *parent_);
        virtual ~object_t ();

        uint32_t get_thread_slot ();
        ctx_t *get_ctx ();
        void process_command (struct command_t &cmd_);

        //  Allow pipe to access corresponding context functions.
        void register_pipe (class pipe_t *pipe_);
        void unregister_pipe (class pipe_t *pipe_);

    protected:

        //  Using following function, socket is able to access global
        //  repository of inproc endpoints.
        int register_endpoint (const char *addr_, class socket_base_t *socket_);
        void unregister_endpoints (class socket_base_t *socket_);
        class socket_base_t *find_endpoint (const char *addr_);

        //  Chooses least loaded I/O thread.
        class io_thread_t *choose_io_thread (uint64_t taskset_);

        //  Derived object can use these functions to send commands
        //  to other objects.
        void send_stop ();
        void send_plug (class owned_t *destination_, bool inc_seqnum_ = true);
        void send_own (class socket_base_t *destination_,
            class owned_t *object_);
        void send_attach (class session_t *destination_,
             struct i_engine *engine_, const blob_t &peer_identity_,
             bool inc_seqnum_ = true);
        void send_bind (class socket_base_t *destination_,
             class reader_t *in_pipe_, class writer_t *out_pipe_,
             const blob_t &peer_identity_, bool inc_seqnum_ = true);
        void send_revive (class object_t *destination_);
        void send_reader_info (class writer_t *destination_,
             uint64_t msgs_read_);
        void send_pipe_term (class writer_t *destination_);
        void send_pipe_term_ack (class reader_t *destination_);
        void send_term_req (class socket_base_t *destination_,
            class owned_t *object_);
        void send_term (class owned_t *destination_);
        void send_term_ack (class socket_base_t *destination_);

        //  These handlers can be overloaded by the derived objects. They are
        //  called when command arrives from another thread.
        virtual void process_stop ();
        virtual void process_plug ();
        virtual void process_own (class owned_t *object_);
        virtual void process_attach (struct i_engine *engine_,
            const blob_t &peer_identity_);
        virtual void process_bind (class reader_t *in_pipe_,
            class writer_t *out_pipe_, const blob_t &peer_identity_);
        virtual void process_revive ();
        virtual void process_reader_info (uint64_t msgs_read_);
        virtual void process_pipe_term ();
        virtual void process_pipe_term_ack ();
        virtual void process_term_req (class owned_t *object_);
        virtual void process_term ();
        virtual void process_term_ack ();

        //  Special handler called after a command that requires a seqnum
        //  was processed. The implementation should catch up with its counter
        //  of processed commands here.
        virtual void process_seqnum ();

    private:

        //  Context provides access to the global state.
        class ctx_t *ctx;

        //  Slot ID of the thread the object belongs to.
        uint32_t thread_slot;

        void send_command (command_t &cmd_);

        object_t (const object_t&);
        void operator = (const object_t&);
    };

}

#endif
