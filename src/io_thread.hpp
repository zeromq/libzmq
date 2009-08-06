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
#include "i_poller.hpp"
#include "i_poll_events.hpp"
#include "fd_signaler.hpp"

namespace zmq
{

    //  Generic part of the I/O thread. Polling-mechanism-specific features
    //  are implemented in separate "polling objects".

    class io_thread_t : public object_t, public i_poll_events
    {
    public:

        io_thread_t (class context_t *context_, int thread_slot_);

        //  Clean-up. If the thread was started, it's neccessary to call 'stop'
        //  before invoking destructor. Otherwise the destructor would hang up.
        ~io_thread_t ();

        //  Launch the physical thread.
        void start ();

        //  Ask underlying thread to stop.
        void stop ();

        //  Returns signaler associated with this I/O thread.
        i_signaler *get_signaler ();

        //  i_poll_events implementation.
        void in_event ();
        void out_event ();
        void timer_event ();

        //  ???
        struct i_poller *get_poller ();

        //  Command handlers.
        void process_stop ();

        //  Returns load experienced by the I/O thread.
        int get_load ();

    private:

        //  Poll thread gets notifications about incoming commands using
        //  this signaler.
        fd_signaler_t signaler;

        //  Handle associated with signaler's file descriptor.
        handle_t signaler_handle;

        //  I/O multiplexing is performed using a poller object.
        i_poller *poller;
    };

}

#endif
