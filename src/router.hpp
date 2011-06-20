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

#ifndef __ZMQ_ROUTER_HPP_INCLUDED__
#define __ZMQ_ROUTER_HPP_INCLUDED__

#include <map>
#include <vector>

#include "socket_base.hpp"
#include "blob.hpp"
#include "msg.hpp"

namespace zmq
{

    //  TODO: This class uses O(n) scheduling. Rewrite it to use O(1) algorithm.
    class router_t :
        public socket_base_t
    {
    public:

        router_t (class ctx_t *parent_, uint32_t tid_);
        ~router_t ();

        //  Overloads of functions from socket_base_t.
        void xattach_pipe (class pipe_t *pipe_, const blob_t &peer_identity_);
        int xsend (class msg_t *msg_, int flags_);
        int xrecv (class msg_t *msg_, int flags_);
        bool xhas_in ();
        bool xhas_out ();
        void xread_activated (class pipe_t *pipe_);
        void xwrite_activated (class pipe_t *pipe_);
        void xterminated (class pipe_t *pipe_);

    protected:

        //  Rollback any message parts that were sent but not yet flushed.
        int rollback ();

    private:

        struct inpipe_t
        {
            class pipe_t *pipe;
            blob_t identity;
            bool active;
        };

        //  Inbound pipes with the names of corresponging peers.
        typedef std::vector <inpipe_t> inpipes_t;
        inpipes_t inpipes;

        //  The pipe we are currently reading from.
        inpipes_t::size_type current_in;

        //  Have we prefetched a message.
        bool prefetched;

        //  Holds the prefetched message.
        msg_t prefetched_msg;

        //  If true, more incoming message parts are expected.
        bool more_in;

        struct outpipe_t
        {
            class pipe_t *pipe;
            bool active;
        };

        //  Outbound pipes indexed by the peer names.
        typedef std::map <blob_t, outpipe_t> outpipes_t;
        outpipes_t outpipes;

        //  The pipe we are currently writing to.
        class pipe_t *current_out;

        //  If true, more outgoing message parts are expected.
        bool more_out;

        router_t (const router_t&);
        const router_t &operator = (const router_t&);
    };

}

#endif
