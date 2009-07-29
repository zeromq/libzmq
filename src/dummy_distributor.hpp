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

#ifndef __ZS_DUMMY_DISTRIBUTOR_HPP_INCLUDED__
#define __ZS_DUMMY_DISTRIBUTOR_HPP_INCLUDED__

#include <vector>

#include <i_demux.hpp>

namespace zs
{

    //  Fake message distributor. There can be only one pipe bound to it
    //  so there no real distribution going on. However, it is more efficient
    //  than a real distributor and should be used where business logic
    //  ensures there'll be at most one pipe bound.

    class dummy_distributor_t : public i_demux
    {
    public:

        dummy_distributor_t ();

        //  i_demux implementation.
        void set_session (class session_t *session_);
        void shutdown ();
        void terminate ();
        void attach_pipe (class pipe_writer_t *pipe_);
        void detach_pipe (class pipe_writer_t *pipe_);
        bool empty ();
        bool send (struct zs_msg *msg_);
        void flush ();

    private:

        //  Clean-up.
        ~dummy_distributor_t ();

        //  Reference to the owner session object.
        class session_t *session;

        //  The bound pipe.
        class pipe_writer_t *pipe;

        dummy_distributor_t (const dummy_distributor_t&);
        void operator = (const dummy_distributor_t&);
    };

}

#endif
