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

#ifndef __ZMQ_XREP_HPP_INCLUDED__
#define __ZMQ_XREP_HPP_INCLUDED__

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
    class xrep_t :
        public socket_base_t
    {
    public:

        xrep_t (zmq::ctx_t *parent_, uint32_t tid_);
        ~xrep_t ();

        //  Overloads of functions from socket_base_t.
        void xattach_pipe (zmq::pipe_t *pipe_);
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

        //  Fair queueing object for inbound pipes.
        fq_t fq;

        //  This value is either 0 (nothing is prefetched), 1 (only message body
        //  is prefetched) or 2 (both identity and message body are prefetched).
        int prefetched;

        //  Holds the prefetched identity.
        blob_t prefetched_id;

        //  Holds the prefetched message.
        msg_t prefetched_msg;

        //  If true, more incoming message parts are expected.
        bool more_in;

        struct outpipe_t
        {
            zmq::pipe_t *pipe;
            bool active;
        };

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

        xrep_t (const xrep_t&);
        const xrep_t &operator = (const xrep_t&);
    };

    class xrep_session_t : public session_base_t
    {
    public:

        xrep_session_t (zmq::io_thread_t *io_thread_, bool connect_,
            socket_base_t *socket_, const options_t &options_,
            const char *protocol_, const char *address_);
        ~xrep_session_t ();

    private:

        xrep_session_t (const xrep_session_t&);
        const xrep_session_t &operator = (const xrep_session_t&);
    };

}

#endif
