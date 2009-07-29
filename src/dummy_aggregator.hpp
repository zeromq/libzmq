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

#ifndef __ZS_DUMMY_AGGREGATOR_HPP_INCLUDED__
#define __ZS_DUMMY_AGGREGATOR_HPP_INCLUDED__

#include <vector>

#include "i_mux.hpp"

namespace zs
{

    //  Fake message aggregator. There can be at most one pipe bound to it,
    //  so there's no real aggregation going on. However, it is more efficient
    //  than a real aggregator. It's intended to be used in the contexts
    //  where business logic ensures there'll be at most one pipe bound.

    class dummy_aggregator_t : public i_mux
    {
    public:

        dummy_aggregator_t ();

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
        ~dummy_aggregator_t ();

        //  Reference to the owner session object.
        class session_t *session;

        //  The single pipe bound.
        class pipe_reader_t *pipe;

        //  If true, the pipe is active.
        bool active;

        dummy_aggregator_t (const dummy_aggregator_t&);
        void operator = (const dummy_aggregator_t&);
    };

}

#endif
