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

#ifndef __ZMQ_FQ_HPP_INCLUDED__
#define __ZMQ_FQ_HPP_INCLUDED__

#include "yarray.hpp"

namespace zmq
{

    //  Class manages a set of inbound pipes. On receive it performs fair
    //  queueing (RFC970) so that senders gone berserk won't cause denial of
    //  service for decent senders.
    class fq_t
    {
    public:

        fq_t ();
        ~fq_t ();

        void attach (class reader_t *pipe_);
        void detach (class reader_t *pipe_);
        void kill (class reader_t *pipe_);
        void revive (class reader_t *pipe_);
        int recv (zmq_msg_t *msg_, int flags_);
        bool has_in ();

    private:

        //  Inbound pipes.
        typedef yarray_t <class reader_t> pipes_t;
        pipes_t pipes;

        //  Number of active pipes. All the active pipes are located at the
        //  beginning of the pipes array.
        pipes_t::size_type active;

        //  Index of the next bound pipe to read a message from.
        pipes_t::size_type current;

        //  If true, part of a multipart message was already received, but
        //  there are following parts still waiting in the current pipe.
        bool more;

        fq_t (const fq_t&);
        void operator = (const fq_t&);
    };

}

#endif
