/* SPDX-License-Identifier: MPL-2.0 */

#include "precompiled.hpp"
#include "macros.hpp"
#include "scatter.hpp"
#include "pipe.hpp"
#include "err.hpp"
#include "msg.hpp"

zmq::scatter_t::scatter_t (class ctx_t *parent_, uint32_t tid_, int sid_) :
    socket_base_t (parent_, tid_, sid_, true)
{
    options.type = ZMQ_SCATTER;
}

zmq::scatter_t::~scatter_t ()
{
}

void zmq::scatter_t::xattach_pipe (pipe_t *pipe_,
                                   bool subscribe_to_all_,
                                   bool locally_initiated_)
{
    LIBZMQ_UNUSED (subscribe_to_all_);
    LIBZMQ_UNUSED (locally_initiated_);

    //  Don't delay pipe termination as there is no one
    //  to receive the delimiter.
    pipe_->set_nodelay ();

    zmq_assert (pipe_);
    _lb.attach (pipe_);
}

void zmq::scatter_t::xwrite_activated (pipe_t *pipe_)
{
    _lb.activated (pipe_);
}

void zmq::scatter_t::xpipe_terminated (pipe_t *pipe_)
{
    _lb.pipe_terminated (pipe_);
}

int zmq::scatter_t::xsend (msg_t *msg_)
{
    //  SCATTER sockets do not allow multipart data (ZMQ_SNDMORE)
    if (msg_->flags () & msg_t::more) {
        errno = EINVAL;
        return -1;
    }

    return _lb.send (msg_);
}

bool zmq::scatter_t::xhas_out ()
{
    return _lb.has_out ();
}
