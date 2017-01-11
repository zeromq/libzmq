/*
    Copyright (c) 2007-2016 Contributors as noted in the AUTHORS file

    This file is part of libzmq, the ZeroMQ core engine in C++.

    libzmq is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License (LGPL) as published
    by the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    As a special exception, the Contributors give you permission to link
    this library with independent modules to produce an executable,
    regardless of the license terms of these independent modules, and to
    copy and distribute the resulting executable under terms of your choice,
    provided that you also meet, for each linked independent module, the
    terms and conditions of the license of that module. An independent
    module is a module which is not derived from or based on this library.
    If you modify this library, you must extend this exception to your
    version of the library.

    libzmq is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
    FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
    License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __ZMQ_OBJECT_HPP_INCLUDED__
#define __ZMQ_OBJECT_HPP_INCLUDED__

#include <string>
#include "stdint.hpp"

namespace zmq
{

    struct i_engine;
    struct endpoint_t;
    struct pending_connection_t;
    struct command_t;
    class ctx_t;
    class pipe_t;
    class socket_base_t;
    class session_base_t;
    class io_thread_t;
    class own_t;

    //  Base class for all objects that participate in inter-thread
    //  communication.

    class object_t
    {
    public:

        object_t (zmq::ctx_t *ctx_, uint32_t tid_);
        object_t (object_t *parent_);
        virtual ~object_t ();

        uint32_t get_tid ();
        void set_tid(uint32_t id);
        ctx_t *get_ctx ();
        void process_command (zmq::command_t &cmd_);
        void send_inproc_connected (zmq::socket_base_t *socket_);
        void send_bind (zmq::own_t *destination_, zmq::pipe_t *pipe_, bool inc_seqnum_ = true);

    protected:

        //  Using following function, socket is able to access global
        //  repository of inproc endpoints.
        int register_endpoint (const char *addr_,
                const zmq::endpoint_t &endpoint_);
        int unregister_endpoint (
                const std::string &addr_, socket_base_t *socket_);
        void unregister_endpoints (zmq::socket_base_t *socket_);
        zmq::endpoint_t find_endpoint (const char *addr_);
        void pend_connection (const std::string &addr_,
                const endpoint_t &endpoint, pipe_t **pipes_);
        void connect_pending (const char *addr_, zmq::socket_base_t *bind_socket_);

        void destroy_socket (zmq::socket_base_t *socket_);

        //  Logs an message.
        void log (const char *format_, ...);

        //  Chooses least loaded I/O thread.
        zmq::io_thread_t *choose_io_thread (uint64_t affinity_);

        //  Derived object can use these functions to send commands
        //  to other objects.
        void send_stop ();
        void send_plug (zmq::own_t *destination_,
            bool inc_seqnum_ = true);
        void send_own (zmq::own_t *destination_,
            zmq::own_t *object_);
        void send_attach (zmq::session_base_t *destination_,
             zmq::i_engine *engine_, bool inc_seqnum_ = true);
        void send_activate_read (zmq::pipe_t *destination_);
        void send_activate_write (zmq::pipe_t *destination_,
             uint64_t msgs_read_);
        void send_hiccup (zmq::pipe_t *destination_, void *pipe_);
        void send_pipe_term (zmq::pipe_t *destination_);
        void send_pipe_term_ack (zmq::pipe_t *destination_);
        void send_pipe_hwm (zmq::pipe_t *destination_, int inhwm_, int outhwm_);
        void send_term_req (zmq::own_t *destination_,
            zmq::own_t *object_);
        void send_term (zmq::own_t *destination_, int linger_);
        void send_term_ack (zmq::own_t *destination_);
        void send_reap (zmq::socket_base_t *socket_);
        void send_reaped ();
        void send_done ();

        //  These handlers can be overridden by the derived objects. They are
        //  called when command arrives from another thread.
        virtual void process_stop ();
        virtual void process_plug ();
        virtual void process_own (zmq::own_t *object_);
        virtual void process_attach (zmq::i_engine *engine_);
        virtual void process_bind (zmq::pipe_t *pipe_);
        virtual void process_activate_read ();
        virtual void process_activate_write (uint64_t msgs_read_);
        virtual void process_hiccup (void *pipe_);
        virtual void process_pipe_term ();
        virtual void process_pipe_term_ack ();
        virtual void process_pipe_hwm (int inhwm_, int outhwm_);
        virtual void process_term_req (zmq::own_t *object_);
        virtual void process_term (int linger_);
        virtual void process_term_ack ();
        virtual void process_reap (zmq::socket_base_t *socket_);
        virtual void process_reaped ();

        //  Special handler called after a command that requires a seqnum
        //  was processed. The implementation should catch up with its counter
        //  of processed commands here.
        virtual void process_seqnum ();

    private:

        //  Context provides access to the global state.
        zmq::ctx_t *ctx;

        //  Thread ID of the thread the object belongs to.
        uint32_t tid;

        void send_command (command_t &cmd_);

        object_t (const object_t&);
        const object_t &operator = (const object_t&);
    };

}

#endif
