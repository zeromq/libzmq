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

#ifndef __ZMQ_CONNECTER_HPP_INCLUDED__
#define __ZMQ_CONNECTER_HPP_INCLUDED__

#include <string>

#include "../include/zmq.h"

#include "i_poller.hpp"
#include "io_object.hpp"
#include "i_poll_events.hpp"
#include "i_session.hpp"
#include "tcp_connecter.hpp"

namespace zmq
{

    class connecter_t : public io_object_t, public i_poll_events,
        public i_session
    {
    public:

        connecter_t (class io_thread_t *thread_, const char *addr_,
            class session_t *session_);

        void terminate ();
        void shutdown ();

        void process_reg (class simple_semaphore_t *smph_);
        void process_unreg (class simple_semaphore_t *smph_);

        //  i_poll_events implementation.
        void in_event ();
        void out_event ();
        void timer_event ();

        //  i_session implementation
        void set_engine (struct i_engine *engine_);
        //  void shutdown ();
        bool read (struct zmq_msg *msg_);
        bool write (struct zmq_msg *msg_);
        void flush ();

    private:

        //  Clean-up.
        ~connecter_t ();

         enum {
             idle,
             waiting,
             connecting,
             sending
         } state;

        //  Cached pointer to the poller.
        struct i_poller *poller;

        //  Handle of the connecting socket.
        handle_t handle;

        //  Associated session. It lives in the same I/O thread.
        class session_t *session;

        //  Address to connect to.
        std::string addr;

        //  Identity of the connection.
        std::string identity;

        tcp_connecter_t tcp_connecter;

        struct i_engine *engine;

        connecter_t (const connecter_t&);
        void operator = (const connecter_t&);
    };

}

#endif
