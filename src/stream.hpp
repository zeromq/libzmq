/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_STREAM_HPP_INCLUDED__
#define __ZMQ_STREAM_HPP_INCLUDED__

#include <map>

#include "router.hpp"

namespace zmq
{
class ctx_t;
class pipe_t;

class stream_t ZMQ_FINAL : public routing_socket_base_t
{
  public:
    stream_t (zmq::ctx_t *parent_, uint32_t tid_, int sid_);
    ~stream_t ();

    //  Overrides of functions from socket_base_t.
    void xattach_pipe (zmq::pipe_t *pipe_,
                       bool subscribe_to_all_,
                       bool locally_initiated_);
    int xsend (zmq::msg_t *msg_);
    int xrecv (zmq::msg_t *msg_);
    bool xhas_in ();
    bool xhas_out ();
    void xread_activated (zmq::pipe_t *pipe_);
    void xpipe_terminated (zmq::pipe_t *pipe_);
    int xsetsockopt (int option_, const void *optval_, size_t optvallen_);

  private:
    //  Generate peer's id and update lookup map
    void identify_peer (pipe_t *pipe_, bool locally_initiated_);

    //  Fair queueing object for inbound pipes.
    fq_t _fq;

    //  True iff there is a message held in the pre-fetch buffer.
    bool _prefetched;

    //  If true, the receiver got the message part with
    //  the peer's identity.
    bool _routing_id_sent;

    //  Holds the prefetched identity.
    msg_t _prefetched_routing_id;

    //  Holds the prefetched message.
    msg_t _prefetched_msg;

    //  The pipe we are currently writing to.
    zmq::pipe_t *_current_out;

    //  If true, more outgoing message parts are expected.
    bool _more_out;

    //  Routing IDs are generated. It's a simple increment and wrap-over
    //  algorithm. This value is the next ID to use (if not used already).
    uint32_t _next_integral_routing_id;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (stream_t)
};
}

#endif
