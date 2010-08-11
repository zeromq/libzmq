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

#ifndef __ZMQ_I_TERMINATE_EVENTS_HPP_INCLUDED__
#define __ZMQ_I_TERMINATE_EVENTS_HPP_INCLUDED__

namespace zmq
{

    //  Algorithms such as fair queueing (fq_t) and load balancing (lb_t)
    //  use this interface to communicate termination event to the socket.

    struct i_terminate_events
    {
        virtual ~i_terminate_events () {}

        virtual void terminated () = 0;
    };

}

#endif
