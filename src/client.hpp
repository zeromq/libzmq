/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_CLIENT_HPP_INCLUDED__
#define __ZMQ_CLIENT_HPP_INCLUDED__

#include "socket_base.hpp"
#include "fq.hpp"
#include "lb.hpp"

namespace zmq
{
class ctx_t;
class msg_t;
class pipe_t;
class io_thread_t;

class client_t ZMQ_FINAL : public socket_base_t
{
  public:
    client_t (zmq::ctx_t *parent_, uint32_t tid_, int sid_);
    ~client_t ();

  protected:
    //  Overrides of functions from socket_base_t.
    void xattach_pipe (zmq::pipe_t *pipe_,
                       bool subscribe_to_all_,
                       bool locally_initiated_);
    int xsend (zmq::msg_t *msg_);
    int xrecv (zmq::msg_t *msg_);
    bool xhas_in ();
    bool xhas_out ();
    void xread_activated (zmq::pipe_t *pipe_);
    void xwrite_activated (zmq::pipe_t *pipe_);
    void xpipe_terminated (zmq::pipe_t *pipe_);

  private:
    //  Messages are fair-queued from inbound pipes. And load-balanced to
    //  the outbound pipes.
    fq_t _fq;
    lb_t _lb;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (client_t)
};
}

#endif
