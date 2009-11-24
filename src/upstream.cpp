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

#include "upstream.hpp"
#include "err.hpp"
#include "pipe.hpp"

zmq::upstream_t::upstream_t (class app_thread_t *parent_) :
    socket_base_t (parent_),
    active (0),
    current (0)
{
    options.requires_in = true;
    options.requires_out = false;
}

zmq::upstream_t::~upstream_t ()
{
}

void zmq::upstream_t::xattach_pipes (class reader_t *inpipe_,
    class writer_t *outpipe_)
{
    zmq_assert (inpipe_ && !outpipe_);

    pipes.push_back (inpipe_);
    pipes.swap (active, pipes.size () - 1);
    active++;
}

void zmq::upstream_t::xdetach_inpipe (class reader_t *pipe_)
{
    //  Remove the pipe from the list; adjust number of active pipes
    //  accordingly.
    zmq_assert (pipe_);
    pipes_t::size_type index = pipes.index (pipe_);
    if (index < active)
        active--;
    pipes.erase (index);
}

void zmq::upstream_t::xdetach_outpipe (class writer_t *pipe_)
{
    //  There are no outpipes, so this function shouldn't be called at all.
    zmq_assert (false);
}

void zmq::upstream_t::xkill (class reader_t *pipe_)
{
    //  Move the pipe to the list of inactive pipes.
    active--;
    pipes.swap (pipes.index (pipe_), active);
}

void zmq::upstream_t::xrevive (class reader_t *pipe_)
{
    //  Move the pipe to the list of active pipes.
    pipes.swap (pipes.index (pipe_), active);
    active++;
}

int zmq::upstream_t::xsetsockopt (int option_, const void *optval_,
    size_t optvallen_)
{
    //  No special options for this socket type.
    errno = EINVAL;
    return -1;
}

int zmq::upstream_t::xsend (zmq_msg_t *msg_, int flags_)
{
    errno = ENOTSUP;
    return -1;
}

int zmq::upstream_t::xflush ()
{
    errno = ENOTSUP;
    return -1;
}

int zmq::upstream_t::xrecv (zmq_msg_t *msg_, int flags_)
{
    //  Deallocate old content of the message.
    zmq_msg_close (msg_);

    //  Round-robin over the pipes to get next message.
    for (int count = active; count != 0; count--) {
        bool fetched = pipes [current]->read (msg_);
        current++;
        if (current >= active)
            current = 0;
        if (fetched)
            return 0;
    }

    //  No message is available. Initialise the output parameter
    //  to be a 0-byte message.
    zmq_msg_init (msg_);
    errno = EAGAIN;
    return -1;
}

bool zmq::upstream_t::xhas_in ()
{
    //  Note that messing with current doesn't break the fairness of fair
    //  queueing algorithm. If there are no messages available current will
    //  get back to its original value. Otherwise it'll point to the first
    //  pipe holding messages, skipping only pipes with no messages available.
    for (int count = active; count != 0; count--) {
        if (pipes [current]->check_read ())
            return true;
        current++;
        if (current >= active)
            current = 0;
    }

    return false;
}

bool zmq::upstream_t::xhas_out ()
{
    return false;
}

