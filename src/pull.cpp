/*
    Copyright (c) 2007-2013 Contributors as noted in the AUTHORS file

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

void zmq::pull_t::xattach_pipe (pipe_t *pipe_, bool subscribe_to_all_)
{
    // subscribe_to_all_ is unused
    (void)subscribe_to_all_;

    zmq_assert (pipe_);
    fq.attach (pipe_);
}

void zmq::pull_t::xread_activated (pipe_t *pipe_)
{
    fq.activated (pipe_);
}

void zmq::pull_t::xpipe_terminated (pipe_t *pipe_)
{
    fq.pipe_terminated (pipe_);
}

int zmq::pull_t::xrecv (msg_t *msg_)
{
    return fq.recv (msg_);
}

bool zmq::pull_t::xhas_in ()
{
    return fq.has_in ();
}
