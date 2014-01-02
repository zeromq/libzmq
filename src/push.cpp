/*
    Copyright (c) 2007-2014 Contributors as noted in the AUTHORS file

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

#include "push.hpp"
#include "pipe.hpp"
#include "err.hpp"
#include "msg.hpp"

zmq::push_t::push_t (class ctx_t *parent_, uint32_t tid_, int sid_) :
    socket_base_t (parent_, tid_, sid_)
{
    options.type = ZMQ_PUSH;
}

zmq::push_t::~push_t ()
{
}

void zmq::push_t::xattach_pipe (pipe_t *pipe_, bool subscribe_to_all_)
{
    // subscribe_to_all_ is unused
    (void)subscribe_to_all_;

    zmq_assert (pipe_);
    lb.attach (pipe_);
}

void zmq::push_t::xwrite_activated (pipe_t *pipe_)
{
    lb.activated (pipe_);
}

void zmq::push_t::xpipe_terminated (pipe_t *pipe_)
{
    lb.pipe_terminated (pipe_);
}

int zmq::push_t::xsend (msg_t *msg_)
{
    return lb.send (msg_);
}

bool zmq::push_t::xhas_out ()
{
    return lb.has_out ();
}
