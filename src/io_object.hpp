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

#ifndef __ZMQ_IO_OBJECT_HPP_INCLUDED__
#define __ZMQ_IO_OBJECT_HPP_INCLUDED__

#include "object.hpp"
#include "i_poller.hpp"
#include "i_poll_events.hpp"

namespace zmq
{

    class io_object_t : public object_t, public i_poll_events
    {
    public:

        //  I/O object will live in the thread inherited from the parent.
        //  However, it's lifetime is managed by the owner.
        io_object_t (class io_thread_t *parent_, object_t *owner_);

    protected:

        //  Ask owner socket to terminate this I/O object. This may not happen
        void term ();

        //  I/O object destroys itself. No point in allowing others to invoke
        //  the destructor. At the same time, it has to be virtual so that
        //  generic io_object deallocation mechanism destroys specific type
        //  of I/O object correctly.
        virtual ~io_object_t ();

        //  Handlers for incoming commands. It vital that every I/O object
        //  invokes io_object_t::process_plug at the end of it's own plug
        //  handler.
        void process_plug ();

        //  Methods to access underlying poller object.
        handle_t add_fd (fd_t fd_, struct i_poll_events *events_);
        void rm_fd (handle_t handle_);
        void set_pollin (handle_t handle_);
        void reset_pollin (handle_t handle_);
        void set_pollout (handle_t handle_);
        void reset_pollout (handle_t handle_);
        void add_timer (struct i_poll_events *events_);
        void cancel_timer (struct i_poll_events *events_);

        //  i_poll_events interface implementation.
        void in_event ();
        void out_event ();
        void timer_event ();

        //  Socket owning this I/O object. It is responsible for destroying
        //  it when it's being closed.
        object_t *owner;

        //  Set to true when object is plugged in. It's responsibility
        //  of derived object to set the property after the feat.
        bool plugged_in;

    private:

        //  Set to true when object was terminated before it was plugged in.
        //  In such case destruction is delayed till 'plug' command arrives.
        bool terminated;

        struct i_poller *poller;

        //  Handlers for incoming commands.
        void process_term ();

        io_object_t (const io_object_t&);
        void operator = (const io_object_t&);
    };

}

#endif
