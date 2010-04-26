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

#include "pair.hpp"
#include "err.hpp"
#include "pipe.hpp"

zmq::pair_t::pair_t (class app_thread_t *parent_) :
    socket_base_t (parent_),
    inpipe (NULL),
    outpipe (NULL),
    alive (true)
{
    options.requires_in = true;
    options.requires_out = true;
}

zmq::pair_t::~pair_t ()
{
    if (inpipe)
        inpipe->term ();
    if (outpipe)
        outpipe->term ();
}

void zmq::pair_t::xattach_pipes (class reader_t *inpipe_,
    class writer_t *outpipe_, const blob_t &peer_identity_)
{
    zmq_assert (!inpipe && !outpipe);
    inpipe = inpipe_;
    outpipe = outpipe_;
    outpipe_alive = true;
}

void zmq::pair_t::xdetach_inpipe (class reader_t *pipe_)
{
    zmq_assert (pipe_ == inpipe);
    inpipe = NULL;
}

void zmq::pair_t::xdetach_outpipe (class writer_t *pipe_)
{
    zmq_assert (pipe_ == outpipe);
    outpipe = NULL;
}

void zmq::pair_t::xkill (class reader_t *pipe_)
{
    zmq_assert (alive);
    alive = false;
}

void zmq::pair_t::xrevive (class reader_t *pipe_)
{
    zmq_assert (!alive);
    alive = true;
}

void zmq::pair_t::xrevive (class writer_t *pipe_)
{
    zmq_assert (!outpipe_alive);
    outpipe_alive = true;
}

int zmq::pair_t::xsetsockopt (int option_, const void *optval_,
    size_t optvallen_)
{
    errno = EINVAL;
    return -1;
}

int zmq::pair_t::xsend (zmq_msg_t *msg_, int flags_)
{
    if (outpipe == NULL || !outpipe_alive) {
        errno = EAGAIN;
        return -1;
    }

    if (!outpipe->write (msg_)) {
        outpipe_alive = false;
        errno = EAGAIN;
        return -1;
    }

    outpipe->flush ();

    //  Detach the original message from the data buffer.
    int rc = zmq_msg_init (msg_);
    zmq_assert (rc == 0);

    return 0;
}

int zmq::pair_t::xrecv (zmq_msg_t *msg_, int flags_)
{
    //  Deallocate old content of the message.
    zmq_msg_close (msg_);

    if (!alive || !inpipe || !inpipe->read (msg_)) {
        errno = EAGAIN;
        return -1;
    }
    return 0;
}

bool zmq::pair_t::xhas_in ()
{
    if (alive && inpipe && inpipe->check_read ())
        return true;
    return false;
}

bool zmq::pair_t::xhas_out ()
{
    if (outpipe == NULL || !outpipe_alive)
        return false;

    outpipe_alive = outpipe->check_write ();
    return outpipe_alive;
}

