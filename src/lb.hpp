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

#ifndef __ZMQ_LB_HPP_INCLUDED__
#define __ZMQ_LB_HPP_INCLUDED__

#include "yarray.hpp"

namespace zmq
{

    //  Class manages a set of outbound pipes. On send it load balances
    //  messages fairly among the pipes.
    class lb_t
    {
    public:

        lb_t ();
        ~lb_t ();

        void attach (class writer_t *pipe_);
        void detach (class writer_t *pipe_);
        void revive (class writer_t *pipe_);
        int send (zmq_msg_t *msg_, int flags_);
        bool has_out ();

    private:

        //  List of outbound pipes.
        typedef yarray_t <class writer_t> pipes_t;
        pipes_t pipes;

        //  Number of active pipes. All the active pipes are located at the
        //  beginning of the pipes array.
        pipes_t::size_type active;

        //  Points to the last pipe that the most recent message was sent to.
        pipes_t::size_type current;

        //  True if last we are in the middle of a multipart message.
        bool more;

        lb_t (const lb_t&);
        void operator = (const lb_t&);
    };

}

#endif
