/*
    Copyright (c) 2007-2011 iMatix Corporation
    Copyright (c) 2007-2011 Other contributors as noted in the AUTHORS file

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "xpub.hpp"
#include "pipe.hpp"
#include "err.hpp"
#include "msg.hpp"

zmq::xpub_t::xpub_t (class ctx_t *parent_, uint32_t tid_) :
    socket_base_t (parent_, tid_),
    dist (this)
{
    options.type = ZMQ_XPUB;
}

zmq::xpub_t::~xpub_t ()
{
}

void zmq::xpub_t::xattach_pipe (pipe_t *pipe_, const blob_t &peer_identity_)
{
    zmq_assert (pipe_);
    pipe_->set_event_sink (this);
    dist.attach (pipe_);
}

void zmq::xpub_t::read_activated (pipe_t *pipe_)
{
    //  PUB socket never receives messages. This should never happen.
    zmq_assert (false);
}

void zmq::xpub_t::write_activated (pipe_t *pipe_)
{
    dist.activated (pipe_);
}

void zmq::xpub_t::terminated (pipe_t *pipe_)
{
    dist.terminated (pipe_);
}

void zmq::xpub_t::process_term (int linger_)
{
    //  Terminate the outbound pipes.
    dist.terminate ();

    //  Continue with the termination immediately.
    socket_base_t::process_term (linger_);
}

int zmq::xpub_t::xsend (msg_t *msg_, int flags_)
{
    return dist.send (msg_, flags_);
}

bool zmq::xpub_t::xhas_out ()
{
    return dist.has_out ();
}

int zmq::xpub_t::xrecv (msg_t *msg_, int flags_)
{
    errno = EAGAIN;
    return -1;
}

bool zmq::xpub_t::xhas_in ()
{
    return false;
}

