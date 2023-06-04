/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_REQ_HPP_INCLUDED__
#define __ZMQ_REQ_HPP_INCLUDED__

#include "dealer.hpp"
#include "stdint.hpp"

namespace zmq
{
class ctx_t;
class msg_t;
class io_thread_t;
class socket_base_t;

class req_t ZMQ_FINAL : public dealer_t
{
  public:
    req_t (zmq::ctx_t *parent_, uint32_t tid_, int sid_);
    ~req_t ();

    //  Overrides of functions from socket_base_t.
    int xsend (zmq::msg_t *msg_);
    int xrecv (zmq::msg_t *msg_);
    bool xhas_in ();
    bool xhas_out ();
    int xsetsockopt (int option_, const void *optval_, size_t optvallen_);
    void xpipe_terminated (zmq::pipe_t *pipe_);

  protected:
    //  Receive only from the pipe the request was sent to, discarding
    //  frames from other pipes.
    int recv_reply_pipe (zmq::msg_t *msg_);

  private:
    //  If true, request was already sent and reply wasn't received yet or
    //  was received partially.
    bool _receiving_reply;

    //  If true, we are starting to send/recv a message. The first part
    //  of the message must be empty message part (backtrace stack bottom).
    bool _message_begins;

    //  The pipe the request was sent to and where the reply is expected.
    zmq::pipe_t *_reply_pipe;

    //  Whether request id frames shall be sent and expected.
    bool _request_id_frames_enabled;

    //  The current request id. It is incremented every time before a new
    //  request is sent.
    uint32_t _request_id;

    //  If false, send() will reset its internal state and terminate the
    //  reply_pipe's connection instead of failing if a previous request is
    //  still pending.
    bool _strict;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (req_t)
};

class req_session_t ZMQ_FINAL : public session_base_t
{
  public:
    req_session_t (zmq::io_thread_t *io_thread_,
                   bool connect_,
                   zmq::socket_base_t *socket_,
                   const options_t &options_,
                   address_t *addr_);
    ~req_session_t ();

    //  Overrides of the functions from session_base_t.
    int push_msg (msg_t *msg_);
    void reset ();

  private:
    enum
    {
        bottom,
        request_id,
        body
    } _state;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (req_session_t)
};
}

#endif
