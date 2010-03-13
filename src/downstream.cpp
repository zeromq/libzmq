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

#include "../include/zmq.h"

#include "downstream.hpp"
#include "err.hpp"
#include "pipe.hpp"

zmq::downstream_t::downstream_t (class app_thread_t *parent_) :
    socket_base_t (parent_)
{
    options.requires_in = false;
    options.requires_out = true;
}

zmq::downstream_t::~downstream_t ()
{
}

void zmq::downstream_t::xattach_pipes (class reader_t *inpipe_,
    class writer_t *outpipe_, const blob_t &peer_identity_)
{
    zmq_assert (!inpipe_ && outpipe_);
    lb.attach (outpipe_);
}

void zmq::downstream_t::xdetach_inpipe (class reader_t *pipe_)
{
    //  There are no inpipes, so this function shouldn't be called at all.
    zmq_assert (false);
}

void zmq::downstream_t::xdetach_outpipe (class writer_t *pipe_)
{
    zmq_assert (pipe_);
    lb.detach (pipe_);
}

void zmq::downstream_t::xkill (class reader_t *pipe_)
{
    //  There are no inpipes, so this function shouldn't be called at all.
    zmq_assert (false);
}

void zmq::downstream_t::xrevive (class reader_t *pipe_)
{
    //  There are no inpipes, so this function shouldn't be called at all.
    zmq_assert (false);
}

void zmq::downstream_t::xrevive (class writer_t *pipe_)
{
    lb.revive (pipe_);
}

int zmq::downstream_t::xsetsockopt (int option_, const void *optval_,
    size_t optvallen_)
{
    //  No special option for this socket type.
    errno = EINVAL;
    return -1;
}

int zmq::downstream_t::xsend (zmq_msg_t *msg_, int flags_)
{
    return lb.send (msg_, flags_);
}

int zmq::downstream_t::xrecv (zmq_msg_t *msg_, int flags_)
{
    errno = ENOTSUP;
    return -1;
}

bool zmq::downstream_t::xhas_in ()
{
    return false;
}

bool zmq::downstream_t::xhas_out ()
{
    return lb.has_out ();
}

