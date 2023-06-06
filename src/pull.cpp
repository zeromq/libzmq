/* SPDX-License-Identifier: MPL-2.0 */

#include "precompiled.hpp"
#include "macros.hpp"
#include "pull.hpp"
#include "err.hpp"
#include "msg.hpp"
#include "pipe.hpp"

zmq::pull_t::pull_t (class ctx_t *parent_, uint32_t tid_, int sid_) :
    socket_base_t (parent_, tid_, sid_)
{
    options.type = ZMQ_PULL;
}

zmq::pull_t::~pull_t ()
{
}

void zmq::pull_t::xattach_pipe (pipe_t *pipe_,
                                bool subscribe_to_all_,
                                bool locally_initiated_)
{
    LIBZMQ_UNUSED (subscribe_to_all_);
    LIBZMQ_UNUSED (locally_initiated_);

    zmq_assert (pipe_);
    _fq.attach (pipe_);
}

void zmq::pull_t::xread_activated (pipe_t *pipe_)
{
    _fq.activated (pipe_);
}

void zmq::pull_t::xpipe_terminated (pipe_t *pipe_)
{
    _fq.pipe_terminated (pipe_);
}

int zmq::pull_t::xrecv (msg_t *msg_)
{
    return _fq.recv (msg_);
}

bool zmq::pull_t::xhas_in ()
{
    return _fq.has_in ();
}
