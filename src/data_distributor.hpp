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

#ifndef __ZS_DATA_DISTRIBUTOR_HPP_INCLUDED__
#define __ZS_DATA_DISTRIBUTOR_HPP_INCLUDED__

#include <vector>

#include <i_demux.hpp>

namespace zs
{

    //  Object to distribute messages to outbound pipes.

    class data_distributor_t : public i_demux
    {
    public:

        data_distributor_t ();

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
        ~data_distributor_t ();

        //  Reference to the owner session object.
        class session_t *session;

        //  Writes the message to the pipe if possible. If it isn't, writes
        //  a gap notification to the pipe.
        void write_to_pipe (class pipe_writer_t *pipe_, struct zs_msg *msg_);

        //  The list of outbound pipes.
        typedef std::vector <class pipe_writer_t*> pipes_t;
        pipes_t pipes;

        data_distributor_t (const data_distributor_t&);
        void operator = (const data_distributor_t&);
    };

}

#endif
