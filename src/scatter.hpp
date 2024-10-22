/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_SCATTER_HPP_INCLUDED__
#define __ZMQ_SCATTER_HPP_INCLUDED__

#include "socket_base.hpp"
#include "session_base.hpp"
#include "lb.hpp"

namespace zmq
{
class ctx_t;
class pipe_t;
class msg_t;
class io_thread_t;

class scatter_t ZMQ_FINAL : public socket_base_t
{
  public:
    scatter_t (zmq::ctx_t *parent_, uint32_t tid_, int sid_);
    ~scatter_t ();

  protected:
    //  Overrides of functions from socket_base_t.
    void xattach_pipe (zmq::pipe_t *pipe_,
                       bool subscribe_to_all_,
                       bool locally_initiated_);
    int xsend (zmq::msg_t *msg_);
    bool xhas_out ();
    void xwrite_activated (zmq::pipe_t *pipe_);
    void xpipe_terminated (zmq::pipe_t *pipe_);

  private:
    //  Load balancer managing the outbound pipes.
    lb_t _lb;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (scatter_t)
};
}

#endif
