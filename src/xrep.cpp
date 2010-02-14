/*
    Copyright (c) 2007-2010 iMatix Corporation

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the Lesser GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    Lesser GNU General Public License for more details.

    You should have received a copy of the Lesser GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "../bindings/c/zmq.h"

#include "xrep.hpp"
#include "err.hpp"

zmq::xrep_t::xrep_t (class app_thread_t *parent_) :
    socket_base_t (parent_)
{
    options.requires_in = true;
    options.requires_out = true;

    //  On connect, pipes are created only after initial handshaking.
    //  That way we are aware of the peer's identity when binding to the pipes.
    options.immediate_connect = false;

    //  XREP socket adds identity to inbound messages and strips identity
    //  from the outbound messages.
    options.traceroute = true;
}

zmq::xrep_t::~xrep_t ()
{
}

void zmq::xrep_t::xattach_pipes (class reader_t *inpipe_,
    class writer_t *outpipe_)
{
    zmq_assert (inpipe_ && outpipe_);
    fq.attach (inpipe_);

    zmq_assert (false);
}

void zmq::xrep_t::xdetach_inpipe (class reader_t *pipe_)
{
    zmq_assert (pipe_);
    fq.detach (pipe_);
}

void zmq::xrep_t::xdetach_outpipe (class writer_t *pipe_)
{
    zmq_assert (false);
}

void zmq::xrep_t::xkill (class reader_t *pipe_)
{
    fq.kill (pipe_);
}

void zmq::xrep_t::xrevive (class reader_t *pipe_)
{
    fq.revive (pipe_);
}

int zmq::xrep_t::xsetsockopt (int option_, const void *optval_,
    size_t optvallen_)
{
    errno = EINVAL;
    return -1;
}

int zmq::xrep_t::xsend (zmq_msg_t *msg_, int flags_)
{
    zmq_assert (false);
    return -1;
}

int zmq::xrep_t::xflush ()
{
    zmq_assert (false);
    return -1;
}

int zmq::xrep_t::xrecv (zmq_msg_t *msg_, int flags_)
{
    return fq.recv (msg_, flags_);
}

bool zmq::xrep_t::xhas_in ()
{
    return fq.has_in ();
}

bool zmq::xrep_t::xhas_out ()
{
    zmq_assert (false);
    return false;
}


