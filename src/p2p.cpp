/*
    Copyright (c) 2007-2009 FastMQ Inc.

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

#include "p2p.hpp"
#include "err.hpp"

zmq::p2p_t::p2p_t (class app_thread_t *parent_) :
    socket_base_t (parent_)
{
    options.requires_in = true;
    options.requires_out = true;
}

zmq::p2p_t::~p2p_t ()
{
}

void zmq::p2p_t::xattach_pipes (class reader_t *inpipe_,
    class writer_t *outpipe_)
{
    zmq_assert (false);
}

void zmq::p2p_t::xdetach_inpipe (class reader_t *pipe_)
{
    zmq_assert (false);
}

void zmq::p2p_t::xdetach_outpipe (class writer_t *pipe_)
{
    zmq_assert (false);
}

void zmq::p2p_t::xkill (class reader_t *pipe_)
{
    zmq_assert (false);
}

void zmq::p2p_t::xrevive (class reader_t *pipe_)
{
    zmq_assert (false);
}

int zmq::p2p_t::xsetsockopt (int option_, const void *optval_,
    size_t optvallen_)
{
    errno = EINVAL;
    return -1;
}

int zmq::p2p_t::xsend (zmq_msg_t *msg_, int flags_)
{
    zmq_assert (false);
    return 0;
}

int zmq::p2p_t::xflush ()
{
    zmq_assert (false);
    return 0;
}

int zmq::p2p_t::xrecv (zmq_msg_t *msg_, int flags_)
{
    zmq_assert (false);
    return 0;
}

bool zmq::p2p_t::xhas_in ()
{
    zmq_assert (false);
    return false;
}

bool zmq::p2p_t::xhas_out ()
{
    zmq_assert (false);
    return false;
}

