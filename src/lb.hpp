/*
    Copyright (c) 2007-2013 Contributors as noted in the AUTHORS file

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __ZMQ_LB_HPP_INCLUDED__
#define __ZMQ_LB_HPP_INCLUDED__

#include "array.hpp"
#include "pipe.hpp"

namespace zmq
{

    //  This class manages a set of outbound pipes. On send it load balances
    //  messages fairly among the pipes.

    class lb_t
    {
    public:

        lb_t ();
        ~lb_t ();

        void attach (pipe_t *pipe_);
        void activated (pipe_t *pipe_);
        void pipe_terminated (pipe_t *pipe_);

        int send (msg_t *msg_);

        //  Sends a message and stores the pipe that was used in pipe_.
        //  It is possible for this function to return success but keep pipe_
        //  unset if the rest of a multipart message to a terminated pipe is
        //  being dropped. For the first frame, this will never happen.
        int sendpipe (msg_t *msg_, pipe_t **pipe_);

        bool has_out ();

    private:

        //  List of outbound pipes.
        typedef array_t <pipe_t, 2> pipes_t;
        pipes_t pipes;

        //  Number of active pipes. All the active pipes are located at the
        //  beginning of the pipes array.
        pipes_t::size_type active;

        //  Points to the last pipe that the most recent message was sent to.
        pipes_t::size_type current;

        //  True if last we are in the middle of a multipart message.
        bool more;

        //  True if we are dropping current message.
        bool dropping;

        lb_t (const lb_t&);
        const lb_t &operator = (const lb_t&);
    };

}

#endif
