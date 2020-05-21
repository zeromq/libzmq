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

#ifndef __ZMQ_XPUB_HPP_INCLUDED__
#define __ZMQ_XPUB_HPP_INCLUDED__

#include <deque>

#include "socket_base.hpp"
#include "session_base.hpp"
#include "mtrie.hpp"
#include "dist.hpp"

namespace zmq
{
class ctx_t;
class msg_t;
class pipe_t;
class io_thread_t;

class xpub_t : public socket_base_t
{
  public:
    xpub_t (zmq::ctx_t *parent_, uint32_t tid_, int sid_);
    ~xpub_t () ZMQ_OVERRIDE;

    //  Implementations of virtual functions from socket_base_t.
    void xattach_pipe (zmq::pipe_t *pipe_,
                       bool subscribe_to_all_ = false,
                       bool locally_initiated_ = false) ZMQ_OVERRIDE;
    int xsend (zmq::msg_t *msg_) ZMQ_FINAL;
    bool xhas_out () ZMQ_FINAL;
    int xrecv (zmq::msg_t *msg_) ZMQ_OVERRIDE;
    bool xhas_in () ZMQ_OVERRIDE;
    void xread_activated (zmq::pipe_t *pipe_) ZMQ_FINAL;
    void xwrite_activated (zmq::pipe_t *pipe_) ZMQ_FINAL;
    int
    xsetsockopt (int option_, const void *optval_, size_t optvallen_) ZMQ_FINAL;
    void xpipe_terminated (zmq::pipe_t *pipe_) ZMQ_FINAL;

  private:
    //  Function to be applied to the trie to send all the subscriptions
    //  upstream.
    static void send_unsubscription (zmq::mtrie_t::prefix_t data_,
                                     size_t size_,
                                     xpub_t *self_);

    //  Function to be applied to each matching pipes.
    static void mark_as_matching (zmq::pipe_t *pipe_, xpub_t *self_);

    //  List of all subscriptions mapped to corresponding pipes.
    mtrie_t _subscriptions;

    //  List of manual subscriptions mapped to corresponding pipes.
    mtrie_t _manual_subscriptions;

    //  Distributor of messages holding the list of outbound pipes.
    dist_t _dist;

    // If true, send all subscription messages upstream, not just
    // unique ones
    bool _verbose_subs;

    // If true, send all unsubscription messages upstream, not just
    // unique ones
    bool _verbose_unsubs;

    //  True if we are in the middle of sending a multi-part message.
    bool _more_send;

    //  True if we are in the middle of receiving a multi-part message.
    bool _more_recv;

    //  If true, subscribe and cancel messages are processed for the rest
    //  of multipart message.
    bool _process_subscribe;

    //  This option is enabled with ZMQ_ONLY_FIRST_SUBSCRIBE.
    //  If true, messages following subscribe/unsubscribe in a multipart
    //  message are treated as user data regardless of the first byte.
    bool _only_first_subscribe;

    //  Drop messages if HWM reached, otherwise return with EAGAIN
    bool _lossy;

    //  Subscriptions will not bed added automatically, only after calling set option with ZMQ_SUBSCRIBE or ZMQ_UNSUBSCRIBE
    bool _manual;

    //  Send message to the last pipe, only used if xpub is on manual and after calling set option with ZMQ_SUBSCRIBE
    bool _send_last_pipe;

    //  Function to be applied to match the last pipe.
    static void mark_last_pipe_as_matching (zmq::pipe_t *pipe_, xpub_t *self_);

    //  Last pipe that sent subscription message, only used if xpub is on manual
    pipe_t *_last_pipe;

    // Pipes that sent subscriptions messages that have not yet been processed, only used if xpub is on manual
    std::deque<pipe_t *> _pending_pipes;

    //  Welcome message to send to pipe when attached
    msg_t _welcome_msg;

    //  List of pending (un)subscriptions, ie. those that were already
    //  applied to the trie, but not yet received by the user.
    std::deque<blob_t> _pending_data;
    std::deque<metadata_t *> _pending_metadata;
    std::deque<unsigned char> _pending_flags;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (xpub_t)
};
}

#endif
