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
    class dist_t
    {
    public:

        dist_t ();
        ~dist_t ();

        //  Adds the pipe to the distributor object.
        void attach (class pipe_t *pipe_);

        //  Activates pipe that have previously reached high watermark.
        void activated (class pipe_t *pipe_);

        //  Mark the pipe as matching. Subsequent call to send_to_matching
        //  will send message also to this pipe.
        void match (class pipe_t *pipe_);

        //  Removes the pipe from the distributor object.
        void terminated (class pipe_t *pipe_);

        //  Send the message to all the outbound pipes. After the call all the
        //  pipes are marked as non-matching.
        int send_to_matching (class msg_t *msg_, int flags_);

        //  Send the message to the matching outbound pipes.
        int send_to_all (class msg_t *msg_, int flags_);

        bool has_out ();

    private:

        //  Write the message to the pipe. Make the pipe inactive if writing
        //  fails. In such a case false is returned.
        bool write (class pipe_t *pipe_, class msg_t *msg_);

        //  Put the message to all active pipes.
        void distribute (class msg_t *msg_, int flags_);

        //  List of outbound pipes.
        typedef array_t <class pipe_t, 2> pipes_t;
        pipes_t pipes;

        //  Number of all the pipes to send the next message to.
        pipes_t::size_type matching;

        //  Number of active pipes. All the active pipes are located at the
        //  beginning of the pipes array. These are the pipes the messages
        //  can be sent to at the moment.
        pipes_t::size_type active;

        //  Number of pipes eligible for sending messages to. This includes all
        //  the active pipes plus all the pipes that we can in theory send
        //  messages to (the HWM is not yet reached), but sending a message
        //  to them would result in partial message being delivered, ie. message
        //  with initial parts missing.
        pipes_t::size_type eligible;

        //  True if last we are in the middle of a multipart message.
        bool more;

        dist_t (const dist_t&);
        const dist_t &operator = (const dist_t&);
    };

}

#endif
