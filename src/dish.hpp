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

class dish_t : public socket_base_t
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

    dish_t (const dish_t &);
    const dish_t &operator= (const dish_t &);
};

class dish_session_t : public session_base_t
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

    dish_session_t (const dish_session_t &);
    const dish_session_t &operator= (const dish_session_t &);
};
}

#endif
