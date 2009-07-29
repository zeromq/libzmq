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

#ifndef __ZS_FAIR_AGGREGATOR_HPP_INCLUDED__
#define __ZS_FAIR_AGGREGATOR_HPP_INCLUDED__

#include <vector>

#include "i_mux.hpp"

namespace zs
{

    //  Object to aggregate messages from inbound pipes.

    class fair_aggregator_t : public i_mux
    {
    public:

        fair_aggregator_t ();

        //  i_mux interface implementation.
        void set_session (session_t *session_);
        void shutdown ();
        void terminate ();
        void attach_pipe (class pipe_reader_t *pipe_);
        void detach_pipe (class pipe_reader_t *pipe_);
        bool empty ();
        void deactivate (class pipe_reader_t *pipe_);
        void reactivate (class pipe_reader_t *pipe_);
        bool recv (struct zs_msg *msg_);


    private:

        //  Clean-up.
        ~fair_aggregator_t ();

        //  Reference to the owner session object.
        class session_t *session;

        //  The list of inbound pipes. The active pipes are occupying indices
        //  from 0 to active-1. Suspended pipes occupy indices from 'active'
        //  to the end of the array.
        typedef std::vector <class pipe_reader_t*> pipes_t;
        pipes_t pipes;

        //  The number of active pipes.
        pipes_t::size_type active;

        //  Pipe to retrieve next message from. The messages are retrieved
        //  from the pipes in round-robin fashion (a.k.a. fair queueing).
        pipes_t::size_type current;

        fair_aggregator_t (const fair_aggregator_t&);
        void operator = (const fair_aggregator_t&);
    };

}

#endif
