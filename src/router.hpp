/*
    Copyright (c) 2009-2011 250bpm s.r.o.
    Copyright (c) 2011 iMatix Corporation
    Copyright (c) 2011 VMware, Inc.
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

#include "socket_base.hpp"
#include "session_base.hpp"
#include "stdint.hpp"
#include "blob.hpp"
#include "msg.hpp"
#include "fq.hpp"

namespace zmq
{

    class ctx_t;
    class pipe_t;

    //  TODO: This class uses O(n) scheduling. Rewrite it to use O(1) algorithm.
    class router_t :
        public socket_base_t
    {
    public:

        router_t (zmq::ctx_t *parent_, uint32_t tid_, int sid);
        ~router_t ();

        //  Overloads of functions from socket_base_t.
        void xattach_pipe (zmq::pipe_t *pipe_, bool icanhasall_);
        int xsetsockopt (int option_, const void *optval_, size_t optvallen_);
        int xsend (msg_t *msg_, int flags_);
        int xrecv (msg_t *msg_, int flags_);
        bool xhas_in ();
        bool xhas_out ();
        void xread_activated (zmq::pipe_t *pipe_);
        void xwrite_activated (zmq::pipe_t *pipe_);
        void xterminated (zmq::pipe_t *pipe_);

    protected:

        //  Rollback any message parts that were sent but not yet flushed.
        int rollback ();

    private:

        //  Receive peer id and update lookup map
        bool identify_peer (pipe_t *pipe_);

        //  Fair queueing object for inbound pipes.
        fq_t fq;

        //  True iff there is a message held in the pre-fetch buffer.
        bool prefetched;

        //  If true, the receiver got the message part with
        //  the peer's identity.
        bool identity_sent;

        //  Holds the prefetched identity.
        msg_t prefetched_id;

        //  Holds the prefetched message.
        msg_t prefetched_msg;

        //  If true, more incoming message parts are expected.
        bool more_in;

        struct outpipe_t
        {
            zmq::pipe_t *pipe;
            bool active;
        };

        //  We keep a set of pipes that have not been identified yet.
        std::set <pipe_t*> anonymous_pipes;

        //  Outbound pipes indexed by the peer IDs.
        typedef std::map <blob_t, outpipe_t> outpipes_t;
        outpipes_t outpipes;

        //  The pipe we are currently writing to.
        zmq::pipe_t *current_out;

        //  If true, more outgoing message parts are expected.
        bool more_out;

        //  Peer ID are generated. It's a simple increment and wrap-over
        //  algorithm. This value is the next ID to use (if not used already).
        uint32_t next_peer_id;

        // If true, report EAGAIN to the caller instead of silently dropping 
        // the message targeting an unknown peer.
        bool mandatory;

        router_t (const router_t&);
        const router_t &operator = (const router_t&);
    };

    class router_session_t : public session_base_t
    {
    public:

        router_session_t (zmq::io_thread_t *io_thread_, bool connect_,
            socket_base_t *socket_, const options_t &options_,
            const address_t *addr_);
        ~router_session_t ();

    private:

        router_session_t (const router_session_t&);
        const router_session_t &operator = (const router_session_t&);
    };

}

#endif
