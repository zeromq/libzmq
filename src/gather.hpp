/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_GATHER_HPP_INCLUDED__
#define __ZMQ_GATHER_HPP_INCLUDED__

#include "socket_base.hpp"
#include "fq.hpp"

namespace zmq
{
class ctx_t;
class pipe_t;
class msg_t;

class gather_t ZMQ_FINAL : public socket_base_t
{
  public:
    gather_t (zmq::ctx_t *parent_, uint32_t tid_, int sid_);
    ~gather_t ();

  protected:
    //  Overrides of functions from socket_base_t.
    void xattach_pipe (zmq::pipe_t *pipe_,
                       bool subscribe_to_all_,
                       bool locally_initiated_);
    int xrecv (zmq::msg_t *msg_);
    bool xhas_in ();
    void xread_activated (zmq::pipe_t *pipe_);
    void xpipe_terminated (zmq::pipe_t *pipe_);

  private:
    //  Fair queueing object for inbound pipes.
    fq_t _fq;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (gather_t)
};
}

#endif
