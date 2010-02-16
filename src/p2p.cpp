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

#include "p2p.hpp"
#include "err.hpp"
#include "pipe.hpp"

zmq::p2p_t::p2p_t (class app_thread_t *parent_) :
    socket_base_t (parent_),
    inpipe (NULL),
    outpipe (NULL),
    alive (true)
{
    options.requires_in = true;
    options.requires_out = true;
}

zmq::p2p_t::~p2p_t ()
{
    if (inpipe)
        inpipe->term ();
    if (outpipe)
        outpipe->term ();
}

void zmq::p2p_t::xattach_pipes (class reader_t *inpipe_,
    class writer_t *outpipe_, const blob_t &peer_identity_)
{
    zmq_assert (!inpipe && !outpipe);
    inpipe = inpipe_;
    outpipe = outpipe_;
}

void zmq::p2p_t::xdetach_inpipe (class reader_t *pipe_)
{
    zmq_assert (pipe_ == inpipe);
    inpipe = NULL;
}

void zmq::p2p_t::xdetach_outpipe (class writer_t *pipe_)
{
    zmq_assert (pipe_ == outpipe);
    outpipe = NULL;
}

void zmq::p2p_t::xkill (class reader_t *pipe_)
{
    zmq_assert (alive);
    alive = false;
}

void zmq::p2p_t::xrevive (class reader_t *pipe_)
{
    zmq_assert (!alive);
    alive = true;
}

int zmq::p2p_t::xsetsockopt (int option_, const void *optval_,
    size_t optvallen_)
{
    errno = EINVAL;
    return -1;
}

int zmq::p2p_t::xsend (zmq_msg_t *msg_, int flags_)
{
    if (!outpipe) {
        errno = EAGAIN;
        return -1;
    }

    //  TODO: Implement this once queue limits are in-place.
    zmq_assert (outpipe->check_write (zmq_msg_size (msg_)));

    outpipe->write (msg_);
    if (!(flags_ & ZMQ_NOFLUSH))
        outpipe->flush ();

    //  Detach the original message from the data buffer.
    int rc = zmq_msg_init (msg_);
    zmq_assert (rc == 0);

    return 0;
}

int zmq::p2p_t::xflush ()
{
    if (outpipe)
        outpipe->flush ();
    return 0;
}

int zmq::p2p_t::xrecv (zmq_msg_t *msg_, int flags_)
{
    //  Deallocate old content of the message.
    zmq_msg_close (msg_);

    if (!alive || !inpipe || !inpipe->read (msg_)) {
        errno = EAGAIN;
        return -1;
    }
    return 0;
}

bool zmq::p2p_t::xhas_in ()
{
    if (alive && inpipe && inpipe->check_read ())
        return true;
    return false;
}

bool zmq::p2p_t::xhas_out ()
{
    //  TODO: Implement this once queue limits are in-place.
    return true;
}

