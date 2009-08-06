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

#ifndef __ZMQ_I_POLLER_HPP_INCLUDED__
#define __ZMQ_I_POLLER_HPP_INCLUDED__

#include "fd.hpp"

namespace zmq
{

    union handle_t
    {
        fd_t fd;
        void *ptr;
    };

    //  Virtual interface to be used when polling on file descriptors.

    struct i_poller
    {
        virtual ~i_poller () {};

        //  Add file descriptor to the polling set. Return handle
        //  representing the descriptor. 'events' interface will be used
        //  to invoke callback functions when event occurs.
        virtual handle_t add_fd (fd_t fd_, struct i_poll_events *events_) = 0;

        //  Remove file descriptor identified by handle from the polling set.
        virtual void rm_fd (handle_t handle_) = 0;

        //  Start polling for input from socket.
        virtual void set_pollin (handle_t handle_) = 0;

        //  Stop polling for input from socket.
        virtual void reset_pollin (handle_t handle_) = 0;

        //  Start polling for availability of the socket for writing.
        virtual void set_pollout (handle_t handle_) = 0;

        //  Stop polling for availability of the socket for writing.
        virtual void reset_pollout (handle_t handle_) = 0;

        //  Ask to be notified after some time. Actual interval varies between
        //  0 and max_timer_period ms. Timer is destroyed once it expires or,
        //  optionally, when cancel_timer is called.
        virtual void add_timer (struct i_poll_events *events_) = 0;

        //  Cancel the timer set by add_timer method.
        virtual void cancel_timer (struct i_poll_events *events_) = 0;

        //  Returns load experienced by the I/O thread. Currently it's number
        //  of file descriptors handled by the poller, in the future we may
        //  use a metric taking actual traffic on the individual sockets into
        //  account.
        virtual int get_load () = 0;

        //  Start the execution of the underlying I/O thread.
        //  This method is called from a foreign thread.
        virtual void start () = 0;

        //  Ask underlying I/O thread to stop.
        virtual void stop () = 0;
    };

}

#endif
