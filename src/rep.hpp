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

#ifndef __ZMQ_REP_HPP_INCLUDED__
#define __ZMQ_REP_HPP_INCLUDED__

#include "socket_base.hpp"
#include "yarray.hpp"

namespace zmq
{

    class rep_t : public socket_base_t
    {
    public:

        rep_t (class app_thread_t *parent_);
        ~rep_t ();

        //  Overloads of functions from socket_base_t.
        void xattach_pipes (class reader_t *inpipe_, class writer_t *outpipe_,
            const blob_t &peer_identity_);
        void xdetach_inpipe (class reader_t *pipe_);
        void xdetach_outpipe (class writer_t *pipe_);
        void xkill (class reader_t *pipe_);
        void xrevive (class reader_t *pipe_);
        void xrevive (class writer_t *pipe_);
        int xsetsockopt (int option_, const void *optval_, size_t optvallen_);
        int xsend (zmq_msg_t *msg_, int flags_);
        int xrecv (zmq_msg_t *msg_, int flags_);
        bool xhas_in ();
        bool xhas_out ();

    private:

        //  List in outbound and inbound pipes. Note that the two lists are
        //  always in sync. I.e. outpipe with index N communicates with the
        //  same session as inpipe with index N.
        typedef yarray_t <class writer_t> out_pipes_t;
        out_pipes_t out_pipes;
        typedef yarray_t <class reader_t> in_pipes_t;
        in_pipes_t in_pipes;

        //  Number of active inpipes. All the active inpipes are located at the
        //  beginning of the in_pipes array.
        in_pipes_t::size_type active;

        //  Index of the next inbound pipe to read a request from.
        in_pipes_t::size_type current;

        //  If true, request was already received and reply wasn't completely
        //  sent yet.
        bool sending_reply;

        //  True, if message processed at the moment (either sent or received)
        //  is processed only partially.
        bool more;

        //  Pipe we are going to send reply to.
        class writer_t *reply_pipe;

        rep_t (const rep_t&);
        void operator = (const rep_t&);

    };

}

#endif
