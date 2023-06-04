/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_DISH_HPP_INCLUDED__
#define __ZMQ_DISH_HPP_INCLUDED__

#include <string>

#include "socket_base.hpp"
#include "session_base.hpp"
#include "dist.hpp"
#include "fq.hpp"
#include "msg.hpp"

namespace zmq
{
class ctx_t;
class pipe_t;
class io_thread_t;

class dish_t ZMQ_FINAL : public socket_base_t
{
  public:
    dish_t (zmq::ctx_t *parent_, uint32_t tid_, int sid_);
    ~dish_t ();

  protected:
    //  Overrides of functions from socket_base_t.
    void xattach_pipe (zmq::pipe_t *pipe_,
                       bool subscribe_to_all_,
                       bool locally_initiated_);
    int xsend (zmq::msg_t *msg_);
    bool xhas_out ();
    int xrecv (zmq::msg_t *msg_);
    bool xhas_in ();
    void xread_activated (zmq::pipe_t *pipe_);
    void xwrite_activated (zmq::pipe_t *pipe_);
    void xhiccuped (pipe_t *pipe_);
    void xpipe_terminated (zmq::pipe_t *pipe_);
    int xjoin (const char *group_);
    int xleave (const char *group_);

  private:
    int xxrecv (zmq::msg_t *msg_);

    //  Send subscriptions to a pipe
    void send_subscriptions (pipe_t *pipe_);

    //  Fair queueing object for inbound pipes.
    fq_t _fq;

    //  Object for distributing the subscriptions upstream.
    dist_t _dist;

    //  The repository of subscriptions.
    typedef std::set<std::string> subscriptions_t;
    subscriptions_t _subscriptions;

    //  If true, 'message' contains a matching message to return on the
    //  next recv call.
    bool _has_message;
    msg_t _message;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (dish_t)
};

class dish_session_t ZMQ_FINAL : public session_base_t
{
  public:
    dish_session_t (zmq::io_thread_t *io_thread_,
                    bool connect_,
                    zmq::socket_base_t *socket_,
                    const options_t &options_,
                    address_t *addr_);
    ~dish_session_t ();

    //  Overrides of the functions from session_base_t.
    int push_msg (msg_t *msg_);
    int pull_msg (msg_t *msg_);
    void reset ();

  private:
    enum
    {
        group,
        body
    } _state;

    msg_t _group_msg;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (dish_session_t)
};
}

#endif
