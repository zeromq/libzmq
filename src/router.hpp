/* SPDX-License-Identifier: MPL-2.0 */

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
