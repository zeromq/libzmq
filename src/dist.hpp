/*
    Copyright (c) 2007-2011 iMatix Corporation
    Copyright (c) 2007-2011 Other contributors as noted in the AUTHORS file

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

#ifndef __ZMQ_DIST_HPP_INCLUDED__
#define __ZMQ_DIST_HPP_INCLUDED__

#include <vector>

#include "array.hpp"
#include "pipe.hpp"

namespace zmq
{

    //  Class manages a set of outbound pipes. It sends each messages to
    //  each of them.
    class dist_t : public i_writer_events
    {
    public:

        dist_t (class own_t *sink_);
        ~dist_t ();

        void attach (writer_t *pipe_);
        void terminate ();
        int send (zmq_msg_t *msg_, int flags_);
        bool has_out ();

        //  i_writer_events interface implementation.
        void activated (writer_t *pipe_);
        void terminated (writer_t *pipe_);

    private:

        //  Write the message to the pipe. Make the pipe inactive if writing
        //  fails. In such a case false is returned.
        bool write (class writer_t *pipe_, zmq_msg_t *msg_);

        //  Put the message to all active pipes.
        void distribute (zmq_msg_t *msg_, int flags_);

        //  Plug in all the delayed pipes.
        void clear_new_pipes ();

        //  List of outbound pipes.
        typedef array_t <class writer_t> pipes_t;
        pipes_t pipes;

        //  List of new pipes that were not yet inserted into 'pipes' list.
        //  These pipes are moves to 'pipes' list once the current multipart
        //  message is fully sent. This way we avoid sending incomplete messages
        //  to peers.
        typedef std::vector <class writer_t*> new_pipes_t;
        new_pipes_t new_pipes;

        //  Number of active pipes. All the active pipes are located at the
        //  beginning of the pipes array.
        pipes_t::size_type active;

        //  True if last we are in the middle of a multipart message.
        bool more;

        //  Object to send events to.
        class own_t *sink;

        //  If true, termination process is already underway.
        bool terminating;

        dist_t (const dist_t&);
        const dist_t &operator = (const dist_t&);
    };

}

#endif
