/* SPDX-License-Identifier: MPL-2.0 */

#include "precompiled.hpp"
#include "macros.hpp"
#include "client.hpp"
#include "err.hpp"
#include "msg.hpp"

zmq::client_t::client_t (class ctx_t *parent_, uint32_t tid_, int sid_) :
    socket_base_t (parent_, tid_, sid_, true)
{
    options.type = ZMQ_CLIENT;
    options.can_send_hello_msg = true;
    options.can_recv_hiccup_msg = true;
}

zmq::client_t::~client_t ()
{
}

void zmq::client_t::xattach_pipe (pipe_t *pipe_,
                                  bool subscribe_to_all_,
                                  bool locally_initiated_)
{
    LIBZMQ_UNUSED (subscribe_to_all_);
    LIBZMQ_UNUSED (locally_initiated_);

    zmq_assert (pipe_);

    _fq.attach (pipe_);
    _lb.attach (pipe_);
}

int zmq::client_t::xsend (msg_t *msg_)
{
    //  CLIENT sockets do not allow multipart data (ZMQ_SNDMORE)
    if (msg_->flags () & msg_t::more) {
        errno = EINVAL;
        return -1;
    }
    return _lb.sendpipe (msg_, NULL);
}

int zmq::client_t::xrecv (msg_t *msg_)
{
    int rc = _fq.recvpipe (msg_, NULL);

    // Drop any messages with more flag
    while (rc == 0 && msg_->flags () & msg_t::more) {
        // drop all frames of the current multi-frame message
        rc = _fq.recvpipe (msg_, NULL);

        while (rc == 0 && msg_->flags () & msg_t::more)
            rc = _fq.recvpipe (msg_, NULL);

        // get the new message
        if (rc == 0)
            rc = _fq.recvpipe (msg_, NULL);
    }

    return rc;
}

bool zmq::client_t::xhas_in ()
{
    return _fq.has_in ();
}

bool zmq::client_t::xhas_out ()
{
    return _lb.has_out ();
}

void zmq::client_t::xread_activated (pipe_t *pipe_)
{
    _fq.activated (pipe_);
}

void zmq::client_t::xwrite_activated (pipe_t *pipe_)
{
    _lb.activated (pipe_);
}

void zmq::client_t::xpipe_terminated (pipe_t *pipe_)
{
    _fq.pipe_terminated (pipe_);
    _lb.pipe_terminated (pipe_);
}
