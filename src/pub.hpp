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

#ifndef __ZMQ_PUB_HPP_INCLUDED__
#define __ZMQ_PUB_HPP_INCLUDED__

#include "socket_base.hpp"
#include "yarray.hpp"
#include "pipe.hpp"

namespace zmq
{

    class pub_t : public socket_base_t, public i_writer_events
    {
    public:

        pub_t (class ctx_t *parent_, uint32_t slot_);
        ~pub_t ();

        //  Implementations of virtual functions from socket_base_t.
        void xattach_pipes (class reader_t *inpipe_, class writer_t *outpipe_,
            const blob_t &peer_identity_);
        void xterm_pipes ();
        bool xhas_pipes ();
        int xsend (zmq_msg_t *msg_, int flags_);
        bool xhas_out ();

        //  i_writer_events interface implementation.
        void activated (writer_t *pipe_);
        void terminated (writer_t *pipe_);

    private:

        //  Write the message to the pipe. Make the pipe inactive if writing
        //  fails. In such a case false is returned.
        bool write (class writer_t *pipe_, zmq_msg_t *msg_);

        //  Outbound pipes, i.e. those the socket is sending messages to.
        typedef yarray_t <class writer_t> pipes_t;
        pipes_t pipes;

        //  Number of active pipes. All the active pipes are located at the
        //  beginning of the pipes array.
        pipes_t::size_type active;

        pub_t (const pub_t&);
        void operator = (const pub_t&);
    };

}

#endif
