/*
    Copyright (c) 2007-2016 Contributors as noted in the AUTHORS file

    This file is part of libzmq, the ZeroMQ core engine in C++.

    libzmq is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License (LGPL) as published
    by the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    As a special exception, the Contributors give you permission to link
    this library with independent modules to produce an executable,
    regardless of the license terms of these independent modules, and to
    copy and distribute the resulting executable under terms of your choice,
    provided that you also meet, for each linked independent module, the
    terms and conditions of the license of that module. An independent
    module is a module which is not derived from or based on this library.
    If you modify this library, you must extend this exception to your
    version of the library.

    libzmq is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
    FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
    License for more details.

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

        //  Overrides of functions from socket_base_t.
        void xattach_pipe (zmq::pipe_t *pipe_, bool subscribe_to_all_);
        int xsetsockopt (int option_, const void *optval_, size_t optvallen_);
        int xsend (zmq::msg_t *msg_);
        int xrecv (zmq::msg_t *msg_);
        bool xhas_in ();
        bool xhas_out ();
        void xread_activated (zmq::pipe_t *pipe_);
        void xwrite_activated (zmq::pipe_t *pipe_);
        void xpipe_terminated (zmq::pipe_t *pipe_);
        int get_peer_state (const void *identity, size_t identity_size) const;

    protected:

        //  Rollback any message parts that were sent but not yet flushed.
        int rollback ();
        const blob_t &get_credential () const;

    private:

        //  Receive peer id and update lookup map
        bool identify_peer (pipe_t *pipe_);

        //  Fair queueing object for inbound pipes.
        fq_t fq;

        //  True iff there is a message held in the pre-fetch buffer.
        bool prefetched;

        //  If true, the receiver got the message part with
        //  the peer's identity.
        bool routing_id_sent;

        //  Holds the prefetched identity.
        msg_t prefetched_id;

        //  Holds the prefetched message.
        msg_t prefetched_msg;

        //  The pipe we are currently reading from
        zmq::pipe_t *current_in;

        //  Should current_in should be terminate after all parts received?
        bool terminate_current_in;

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

        //  Routing IDs are generated. It's a simple increment and wrap-over
        //  algorithm. This value is the next ID to use (if not used already).
        uint32_t next_integral_routing_id;

        // If true, report EAGAIN to the caller instead of silently dropping
        // the message targeting an unknown peer.
        bool mandatory;
        bool raw_socket;

        // if true, send an empty message to every connected router peer
        bool probe_router;

        // If true, the router will reassign an identity upon encountering a
        // name collision. The new pipe will take the identity, the old pipe
        // will be terminated.
        bool handover;

        router_t (const router_t&);
        const router_t &operator = (const router_t&);
    };

}

#endif
