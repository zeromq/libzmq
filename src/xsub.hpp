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

#ifndef __ZMQ_XSUB_HPP_INCLUDED__
#define __ZMQ_XSUB_HPP_INCLUDED__

#include "socket_base.hpp"
#include "session_base.hpp"
#include "dist.hpp"
#include "fq.hpp"
#ifdef ZMQ_USE_RADIX_TREE
#include "radix_tree.hpp"
#else
#include "trie.hpp"
#endif

namespace zmq
{
class ctx_t;
class pipe_t;
class io_thread_t;

class xsub_t : public socket_base_t
{
  public:
    xsub_t (zmq::ctx_t *parent_, uint32_t tid_, int sid_);
    ~xsub_t () ZMQ_OVERRIDE;

  protected:
    //  Overrides of functions from socket_base_t.
    void xattach_pipe (zmq::pipe_t *pipe_,
                       bool subscribe_to_all_,
                       bool locally_initiated_) ZMQ_FINAL;
    int xsetsockopt (int option_,
                     const void *optval_,
                     size_t optvallen_) ZMQ_OVERRIDE;
    int xsend (zmq::msg_t *msg_) ZMQ_OVERRIDE;
    bool xhas_out () ZMQ_OVERRIDE;
    int xrecv (zmq::msg_t *msg_) ZMQ_FINAL;
    bool xhas_in () ZMQ_FINAL;
    void xread_activated (zmq::pipe_t *pipe_) ZMQ_FINAL;
    void xwrite_activated (zmq::pipe_t *pipe_) ZMQ_FINAL;
    void xhiccuped (pipe_t *pipe_) ZMQ_FINAL;
    void xpipe_terminated (zmq::pipe_t *pipe_) ZMQ_FINAL;

  private:
    //  Check whether the message matches at least one subscription.
    bool match (zmq::msg_t *msg_);

    //  Function to be applied to the trie to send all the subsciptions
    //  upstream.
    static void
    send_subscription (unsigned char *data_, size_t size_, void *arg_);

    //  Fair queueing object for inbound pipes.
    fq_t _fq;

    //  Object for distributing the subscriptions upstream.
    dist_t _dist;

    //  The repository of subscriptions.
#ifdef ZMQ_USE_RADIX_TREE
    radix_tree_t _subscriptions;
#else
    trie_t _subscriptions;
#endif

    //  If true, 'message' contains a matching message to return on the
    //  next recv call.
    bool _has_message;
    msg_t _message;

    //  If true, part of a multipart message was already sent, but
    //  there are following parts still waiting.
    bool _more_send;

    //  If true, part of a multipart message was already received, but
    //  there are following parts still waiting.
    bool _more_recv;

    //  If true, subscribe and cancel messages are processed for the rest
    //  of multipart message.
    bool _process_subscribe;

    //  This option is enabled with ZMQ_ONLY_FIRST_SUBSCRIBE.
    //  If true, messages following subscribe/unsubscribe in a multipart
    //  message are treated as user data regardless of the first byte.
    bool _only_first_subscribe;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (xsub_t)
};
}

#endif
