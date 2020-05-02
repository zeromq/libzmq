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
class router_t : public routing_socket_base_t
{
  public:
    router_t (zmq::ctx_t *parent_, uint32_t tid_, int sid_);
    ~router_t () ZMQ_OVERRIDE;

    //  Overrides of functions from socket_base_t.
    void xattach_pipe (zmq::pipe_t *pipe_,
                       bool subscribe_to_all_,
                       bool locally_initiated_) ZMQ_FINAL;
    int
    xsetsockopt (int option_, const void *optval_, size_t optvallen_) ZMQ_FINAL;
    int xsend (zmq::msg_t *msg_) ZMQ_OVERRIDE;
    int xrecv (zmq::msg_t *msg_) ZMQ_OVERRIDE;
    bool xhas_in () ZMQ_OVERRIDE;
    bool xhas_out () ZMQ_OVERRIDE;
    void xread_activated (zmq::pipe_t *pipe_) ZMQ_FINAL;
    void xpipe_terminated (zmq::pipe_t *pipe_) ZMQ_FINAL;
    int get_peer_state (const void *routing_id_,
                        size_t routing_id_size_) const ZMQ_FINAL;

  protected:
    //  Rollback any message parts that were sent but not yet flushed.
    int rollback ();

  private:
    //  Receive peer id and update lookup map
    bool identify_peer (pipe_t *pipe_, bool locally_initiated_);

    //  Fair queueing object for inbound pipes.
    fq_t _fq;

    //  True iff there is a message held in the pre-fetch buffer.
    bool _prefetched;

    //  If true, the receiver got the message part with
    //  the peer's identity.
    bool _routing_id_sent;

    //  Holds the prefetched identity.
    msg_t _prefetched_id;

    //  Holds the prefetched message.
    msg_t _prefetched_msg;

    //  The pipe we are currently reading from
    zmq::pipe_t *_current_in;

    //  Should current_in should be terminate after all parts received?
    bool _terminate_current_in;

    //  If true, more incoming message parts are expected.
    bool _more_in;

    //  We keep a set of pipes that have not been identified yet.
    std::set<pipe_t *> _anonymous_pipes;

    //  The pipe we are currently writing to.
    zmq::pipe_t *_current_out;

    //  If true, more outgoing message parts are expected.
    bool _more_out;

    //  Routing IDs are generated. It's a simple increment and wrap-over
    //  algorithm. This value is the next ID to use (if not used already).
    uint32_t _next_integral_routing_id;

    // If true, report EAGAIN to the caller instead of silently dropping
    // the message targeting an unknown peer.
    bool _mandatory;
    bool _raw_socket;

    // if true, send an empty message to every connected router peer
    bool _probe_router;

    // If true, the router will reassign an identity upon encountering a
    // name collision. The new pipe will take the identity, the old pipe
    // will be terminated.
    bool _handover;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (router_t)
};
}

#endif
