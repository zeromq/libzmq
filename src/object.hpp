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

#ifndef __ZMQ_OBJECT_HPP_INCLUDED__
#define __ZMQ_OBJECT_HPP_INCLUDED__

#include "stdint.hpp"

namespace zmq
{

    //  Base class for all objects that participate in inter-thread
    //  communication.

    class object_t
    {
    public:

        object_t (class context_t *context_, int thread_slot_);
        object_t (object_t *parent_);
        ~object_t ();

        int get_thread_slot ();
        void process_command (struct command_t &cmd_);

    protected:

        //  Derived object can use following functions to interact with
        //  global repositories. See context.hpp for function details.
        int thread_slot_count ();
        class io_thread_t *choose_io_thread (uint64_t taskset_);

        //  Derived object can use these functions to send commands
        //  to other objects.
        void send_stop ();
        void send_bind (object_t *destination_, class pipe_reader_t *reader_,
            class session_t *peer_);
        void send_head (object_t *destination_, uint64_t bytes_);
        void send_tail (object_t *destination_, uint64_t bytes_);
        void send_reg (object_t *destination_,
            class simple_semaphore_t *smph_);
        void send_reg_and_bind (object_t *destination_, class session_t *peer_,
            bool flow_in_, bool flow_out_);
        void send_unreg (object_t *destination_,
            class simple_semaphore_t *smph_);
        void send_engine (object_t *destination_, struct i_engine *engine_);
        void send_terminate (object_t *destination_);
        void send_terminate_ack (object_t *destination_);

        //  These handlers can be overloaded by the derived objects. They are
        //  called when command arrives from another thread.
        virtual void process_stop ();
        virtual void process_bind (class pipe_reader_t *reader_,
            class session_t *peer_);
        virtual void process_head (uint64_t bytes_);
        virtual void process_tail (uint64_t bytes_);
        virtual void process_reg (class simple_semaphore_t *smph_);
        virtual void process_reg_and_bind (class session_t *peer_,
            bool flow_in_, bool flow_out_);
        virtual void process_unreg (class simple_semaphore_t *smph_);
        virtual void process_engine (struct i_engine *engine_);
        virtual void process_terminate ();
        virtual void process_terminate_ack ();

        //  Pointer to the root of the infrastructure.
        class context_t *context;

        //  Slot ID of the thread the object belongs to.
        int thread_slot;

    private:

        void send_command (command_t &cmd_);

        object_t (const object_t&);
        void operator = (const object_t&);
    };

}

#endif
