/*
    Copyright (c) 2009-2011 250bpm s.r.o.
    Copyright (c) 2007-2010 iMatix Corporation
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

#include "push.hpp"
#include "pipe.hpp"
#include "err.hpp"
#include "msg.hpp"

zmq::push_t::push_t (class ctx_t *parent_, uint32_t tid_) :
    socket_base_t (parent_, tid_)
{
    options.type = ZMQ_PUSH;
}

zmq::push_t::~push_t ()
{
}

void zmq::push_t::xattach_pipe (pipe_t *pipe_)
{
    zmq_assert (pipe_);
    lb.attach (pipe_);
}

void zmq::push_t::xwrite_activated (pipe_t *pipe_)
{
    lb.activated (pipe_);
}

void zmq::push_t::xterminated (pipe_t *pipe_)
{
    lb.terminated (pipe_);
}

int zmq::push_t::xsend (msg_t *msg_, int flags_)
{
    return lb.send (msg_, flags_);
}

bool zmq::push_t::xhas_out ()
{
    return lb.has_out ();
}

zmq::push_session_t::push_session_t (io_thread_t *io_thread_, bool connect_,
      socket_base_t *socket_, const options_t &options_,
      const char *protocol_, const char *address_) :
    session_base_t (io_thread_, connect_, socket_, options_, protocol_,
        address_)
{
}

zmq::push_session_t::~push_session_t ()
{
}

