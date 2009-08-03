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

#ifndef __ZMQ_IO_THREAD_HPP_INCLUDED__
#define __ZMQ_IO_THREAD_HPP_INCLUDED__

#include <vector>

#include "object.hpp"
#include "i_thread.hpp"
#include "i_poller.hpp"
#include "i_poll_events.hpp"
#include "fd_signaler.hpp"

namespace zmq
{

    //  Generic part of the I/O thread. Polling-mechanism-specific features
    //  are implemented in separate "polling objects".

    class io_thread_t : public object_t, public i_poll_events, public i_thread
    {
    public:

        io_thread_t (class dispatcher_t *dispatcher_, int thread_slot_);

        //  Launch the physical thread.
        void start ();

        //  Ask underlying thread to stop.
        void stop ();

        //  Wait till undelying thread terminates.
        void join ();

        //  To be called when the whole infrastrucure is being closed (zmq_term).
        //  It's vital to call the individual commands in this sequence:
        //  stop, join, shutdown.
        void shutdown ();

        //  Returns signaler associated with this I/O thread.
        i_signaler *get_signaler ();

        //  i_poll_events implementation.
        void in_event ();
        void out_event ();
        void timer_event ();

        //  i_thread implementation.
        void attach_session (class session_t *session_);
        void detach_session (class session_t *session_);
        struct i_poller *get_poller ();

        //  Command handlers.
        void process_stop ();

        //  Returns load experienced by the I/O thread.
        int get_load ();

    private:

        //  Clean-up.
        ~io_thread_t ();

        //  Poll thread gets notifications about incoming commands using
        //  this signaler.
        fd_signaler_t signaler;

        //  Handle associated with signaler's file descriptor.
        handle_t signaler_handle;

        //  I/O multiplexing is performed using a poller object.
        i_poller *poller;

        //  Vector of all sessions associated with this app thread.
        typedef std::vector <class session_t*> sessions_t;
        sessions_t sessions;

    };

}

#endif
