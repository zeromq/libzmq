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

#ifndef __ZMQ_ZMQ_CONNECTER_HPP_INCLUDED__
#define __ZMQ_ZMQ_CONNECTER_HPP_INCLUDED__

#include "io_object.hpp"
#include "tcp_connecter.hpp"

namespace zmq
{

    class zmq_connecter_t : public io_object_t
    {
    public:

        zmq_connecter_t (class io_thread_t *parent_, object_t *owner_);

        //  Set IP address to connect to.
        int set_address (const char *addr_);

    private:

        ~zmq_connecter_t ();

        //  Handlers for incoming commands.
        void process_plug ();
        void process_unplug ();

        //  Handlers for I/O events.
        void in_event ();
        void out_event ();
        void timer_event ();

        //  Internal function to start the actual connection establishment.
        void start_connecting ();

        //  Actual connecting socket.
        tcp_connecter_t tcp_connecter;

        //  Handle corresponding to the listening socket.
        handle_t handle;

        //  True, if we are waiting for a period of time before trying to
        //  reconnect.
        bool waiting;

        zmq_connecter_t (const zmq_connecter_t&);
        void operator = (const zmq_connecter_t&);
    };

}

#endif
