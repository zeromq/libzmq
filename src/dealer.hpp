/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_DEALER_HPP_INCLUDED__
#define __ZMQ_DEALER_HPP_INCLUDED__

#include "socket_base.hpp"
#include "session_base.hpp"
#include "fq.hpp"
#include "lb.hpp"

namespace zmq
{
class ctx_t;
class msg_t;
class pipe_t;
class io_thread_t;
class socket_base_t;

class dealer_t : public socket_base_t
{
  public:
    dealer_t (zmq::ctx_t *parent_, uint32_t tid_, int sid_);
    ~dealer_t () ZMQ_OVERRIDE;

  protected:
    //  Overrides of functions from socket_base_t.
    void xattach_pipe (zmq::pipe_t *pipe_,
                       bool subscribe_to_all_,
                       bool locally_initiated_) ZMQ_FINAL;
    int xsetsockopt (int option_,
                     const void *optval_,
                     size_t optvallen_) ZMQ_OVERRIDE;
    int xsend (zmq::msg_t *msg_) ZMQ_OVERRIDE;
    int xrecv (zmq::msg_t *msg_) ZMQ_OVERRIDE;
    bool xhas_in () ZMQ_OVERRIDE;
    bool xhas_out () ZMQ_OVERRIDE;
    void xread_activated (zmq::pipe_t *pipe_) ZMQ_FINAL;
    void xwrite_activated (zmq::pipe_t *pipe_) ZMQ_FINAL;
    void xpipe_terminated (zmq::pipe_t *pipe_) ZMQ_OVERRIDE;

    //  Send and recv - knowing which pipe was used.
    int sendpipe (zmq::msg_t *msg_, zmq::pipe_t **pipe_);
    int recvpipe (zmq::msg_t *msg_, zmq::pipe_t **pipe_);

  private:
    //  Messages are fair-queued from inbound pipes. And load-balanced to
    //  the outbound pipes.
    fq_t _fq;
    lb_t _lb;

    // if true, send an empty message to every connected router peer
    bool _probe_router;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (dealer_t)
};
}

#endif
