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

#include "xreq.hpp"
#include "err.hpp"

zmq::xreq_t::xreq_t (class app_thread_t *parent_) :
    socket_base_t (parent_),
    dropping (false)
{
    options.requires_in = true;
    options.requires_out = true;
}

zmq::xreq_t::~xreq_t ()
{
}

void zmq::xreq_t::xattach_pipes (class reader_t *inpipe_,
    class writer_t *outpipe_, const blob_t &peer_identity_)
{
    zmq_assert (inpipe_ && outpipe_);
    fq.attach (inpipe_);
    lb.attach (outpipe_);
}

void zmq::xreq_t::xdetach_inpipe (class reader_t *pipe_)
{
    zmq_assert (pipe_);
    fq.detach (pipe_);
}

void zmq::xreq_t::xdetach_outpipe (class writer_t *pipe_)
{
    zmq_assert (pipe_);
    lb.detach (pipe_);
}

void zmq::xreq_t::xkill (class reader_t *pipe_)
{
    fq.kill (pipe_);
}

void zmq::xreq_t::xrevive (class reader_t *pipe_)
{
    fq.revive (pipe_);
}

void zmq::xreq_t::xrevive (class writer_t *pipe_)
{
    lb.revive (pipe_);
}

int zmq::xreq_t::xsetsockopt (int option_, const void *optval_,
    size_t optvallen_)
{
    errno = EINVAL;
    return -1;
}

int zmq::xreq_t::xsend (zmq_msg_t *msg_, int flags_)
{
    while (true) {

        //  If we are ignoring the current message, just drop it and return.
        if (dropping) {
            if (!(msg_->flags & ZMQ_MSG_MORE))
                dropping = false;
            int rc = zmq_msg_close (msg_);
            zmq_assert (rc == 0);
            rc = zmq_msg_init (msg_);
            zmq_assert (rc == 0);
            return 0;
        }

        int rc = lb.send (msg_, flags_);
        if (rc != 0 && errno == EAGAIN)
            dropping = true;
        else
            return rc;
    }
}

int zmq::xreq_t::xrecv (zmq_msg_t *msg_, int flags_)
{
    return fq.recv (msg_, flags_);
}

bool zmq::xreq_t::xhas_in ()
{
    return fq.has_in ();
}

bool zmq::xreq_t::xhas_out ()
{
    //  Socket is always ready for writing. When the queue is full, message
    //  will be silently dropped.
    return true;
}

