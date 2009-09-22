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

#include "req.hpp"
#include "err.hpp"
#include "pipe.hpp"

zmq::req_t::req_t (class app_thread_t *parent_) :
    socket_base_t (parent_),
    current (0),
    waiting_for_reply (false),
    reply_pipe_active (false),
    reply_pipe (NULL)
{
    options.requires_in = true;
    options.requires_out = true;
}

zmq::req_t::~req_t ()
{
}

void zmq::req_t::xattach_pipes (class reader_t *inpipe_,
    class writer_t *outpipe_)
{
    zmq_assert (inpipe_ && outpipe_);
    zmq_assert (in_pipes.size () == out_pipes.size ());

    in_pipes.push_back (inpipe_);
    out_pipes.push_back (outpipe_);
}

void zmq::req_t::xdetach_inpipe (class reader_t *pipe_)
{
    zmq_assert (pipe_);
    zmq_assert (in_pipes.size () == out_pipes.size ());

    //  TODO: The pipe we are awaiting the reply from is detached. What now?
    //  Return ECONNRESET from subsequent recv?
    if (waiting_for_reply && pipe_ == reply_pipe) {
        zmq_assert (false);
    }

    in_pipes_t::size_type index = in_pipes.index (pipe_);

    //  If corresponding outpipe is still in place simply nullify the pointer
    //  to the inpipe.
    if (out_pipes [index]) {
        in_pipes [index] = NULL;
        return;
    }

    //  Now both inpipe and outpipe are detached. Remove them from the lists.
    in_pipes.erase (index);
    out_pipes.erase (index);
}

void zmq::req_t::xdetach_outpipe (class writer_t *pipe_)
{
    zmq_assert (pipe_);
    zmq_assert (in_pipes.size () == out_pipes.size ());

    out_pipes_t::size_type index = out_pipes.index (pipe_);

    //  If corresponding inpipe is still in place simply nullify the pointer
    //  to the outpipe.
    if (in_pipes [index]) {
        out_pipes [index] = NULL;
        return;
    }

    //  Now both inpipe and outpipe are detached. Remove them from the lists.
    in_pipes.erase (index);
    out_pipes.erase (index);
}

void zmq::req_t::xkill (class reader_t *pipe_)
{
    zmq_assert (pipe_ == reply_pipe);

    reply_pipe_active = false;
}

void zmq::req_t::xrevive (class reader_t *pipe_)
{
    //  TODO: Actually, misbehaving peer can cause this kind of thing.
    //  Handle it decently, presumably kill the offending connection.
    zmq_assert (pipe_ == reply_pipe);

    reply_pipe_active = true;
}

int zmq::req_t::xsetsockopt (int option_, const void *optval_,
    size_t optvallen_)
{
    errno = EINVAL;
    return -1;
}

int zmq::req_t::xsend (struct zmq_msg_t *msg_, int flags_)
{
    //  If we've sent a request and we still haven't got the reply,
    //  we can't send another request.
    if (waiting_for_reply) {
        errno = EFSM;
        return -1;
    }

    if (out_pipes.empty ()) {
        errno = EAGAIN;
        return -1;
    }

    current++;
    if (current >= out_pipes.size ())
        current = 0;

    //  TODO: Infinite loop can result here. Integrate the algorithm with
    //  the active pipes list (i.e. pipe pair that has one pipe missing is
    //  considered to be inactive.
    while (!in_pipes [current] || !out_pipes [current]) {
        current++;
        if (current >= out_pipes.size ())
            current = 0;
    }

    //  TODO: Implement this once queue limits are in-place.
    zmq_assert (out_pipes [current]->check_write (zmq_msg_size (msg_)));

    //  Push message to the selected pipe.
    out_pipes [current]->write (msg_);
    out_pipes [current]->flush ();

    waiting_for_reply = true;
    reply_pipe = in_pipes [current];

    //  We can safely assume that the reply pipe is active as the last time
    //  we've used it we've read the reply and haven't tried to read from it
    //  anymore.
    reply_pipe_active = true;

    //  Detach the message from the data buffer.
    int rc = zmq_msg_init (msg_);
    zmq_assert (rc == 0);

    return 0;
}

int zmq::req_t::xflush ()
{
    errno = ENOTSUP;
    return -1;
}

int zmq::req_t::xrecv (struct zmq_msg_t *msg_, int flags_)
{
    //  Deallocate old content of the message.
    zmq_msg_close (msg_);

    //  If request wasn't send, we can't wait for reply.
    if (!waiting_for_reply) {
        zmq_msg_init (msg_);
        errno = EFSM;
        return -1;
    }

    //  Get the reply from the reply pipe.
    if (!reply_pipe_active || !reply_pipe->read (msg_)) {
        zmq_msg_init (msg_);
        errno = EAGAIN;
        return -1;
    }

    waiting_for_reply = false;
    reply_pipe = NULL;

    return 0;
}


