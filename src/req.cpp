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

#include "req.hpp"
#include "err.hpp"
#include "pipe.hpp"

zmq::req_t::req_t (class app_thread_t *parent_) :
    socket_base_t (parent_),
    active (0),
    current (0),
    receiving_reply (false),
    reply_pipe_active (false),
    more (false),
    reply_pipe (NULL)
{
    options.requires_in = true;
    options.requires_out = true;
}

zmq::req_t::~req_t ()
{
}

void zmq::req_t::xattach_pipes (class reader_t *inpipe_,
    class writer_t *outpipe_, const blob_t &peer_identity_)
{
    zmq_assert (inpipe_ && outpipe_);
    zmq_assert (in_pipes.size () == out_pipes.size ());

    in_pipes.push_back (inpipe_);
    in_pipes.swap (active, in_pipes.size () - 1);

    out_pipes.push_back (outpipe_);
    out_pipes.swap (active, out_pipes.size () - 1);

    active++;
}

void zmq::req_t::xdetach_inpipe (class reader_t *pipe_)
{
    zmq_assert (!receiving_reply || !more || reply_pipe != pipe_);

    zmq_assert (pipe_);
    zmq_assert (in_pipes.size () == out_pipes.size ());

    //  TODO: The pipe we are awaiting the reply from is detached. What now?
    //  Return ECONNRESET from subsequent recv?
    if (receiving_reply && pipe_ == reply_pipe) {
        zmq_assert (false);
    }

    in_pipes_t::size_type index = in_pipes.index (pipe_);

    if (out_pipes [index])
        out_pipes [index]->term ();
    in_pipes.erase (index);
    out_pipes.erase (index);
    if (index < active) {
        active--;
        if (current == active)
            current = 0;
    }
}

void zmq::req_t::xdetach_outpipe (class writer_t *pipe_)
{
    zmq_assert (receiving_reply || !more || out_pipes [current] != pipe_);

    zmq_assert (pipe_);
    zmq_assert (in_pipes.size () == out_pipes.size ());

    out_pipes_t::size_type index = out_pipes.index (pipe_);

    if (in_pipes [index])
        in_pipes [index]->term ();
    in_pipes.erase (index);
    out_pipes.erase (index);
    if (index < active) {
        active--;
        if (current == active)
            current = 0;
    }
}

void zmq::req_t::xkill (class reader_t *pipe_)
{
    zmq_assert (receiving_reply);
    zmq_assert (pipe_ == reply_pipe);

    reply_pipe_active = false;
}

void zmq::req_t::xrevive (class reader_t *pipe_)
{
    if (pipe_ == reply_pipe)
        reply_pipe_active = true;
}

void zmq::req_t::xrevive (class writer_t *pipe_)
{
    out_pipes_t::size_type index = out_pipes.index (pipe_);
    zmq_assert (index >= active);

    if (in_pipes [index] != NULL) {
        in_pipes.swap (index, active);
        out_pipes.swap (index, active);
        active++;
    }
}

int zmq::req_t::xsetsockopt (int option_, const void *optval_,
    size_t optvallen_)
{
    errno = EINVAL;
    return -1;
}

int zmq::req_t::xsend (zmq_msg_t *msg_, int flags_)
{
    //  If we've sent a request and we still haven't got the reply,
    //  we can't send another request.
    if (receiving_reply) {
        errno = EFSM;
        return -1;
    }

    while (active > 0) {
        if (out_pipes [current]->check_write ())
            break;

        zmq_assert (!more);
        active--;
        if (current < active) {
            in_pipes.swap (current, active);
            out_pipes.swap (current, active);
        }
        else
            current = 0;
    }

    if (active == 0) {
        errno = EAGAIN;
        return -1;
    }

    //  If we are starting to send the request, generate a prefix.
    if (!more) {
        zmq_msg_t prefix;
        int rc = zmq_msg_init (&prefix);
        zmq_assert (rc == 0);
        prefix.flags |= ZMQ_MSG_MORE;
        bool written = out_pipes [current]->write (&prefix);
        zmq_assert (written);
    }

    //  Push the message to the selected pipe.
    bool written = out_pipes [current]->write (msg_);
    zmq_assert (written);
    more = msg_->flags & ZMQ_MSG_MORE;
    if (!more) {
        out_pipes [current]->flush ();
        receiving_reply = true;
        reply_pipe = in_pipes [current];

        //  We can safely assume that the reply pipe is active as the last time
        //  we've used it we've read the reply and haven't tried to read from it
        //  anymore.
        reply_pipe_active = true;

        //  Move to the next pipe (load-balancing).
        current = (current + 1) % active;
    }

    //  Detach the message from the data buffer.
    int rc = zmq_msg_init (msg_);
    zmq_assert (rc == 0);

    return 0;
}

int zmq::req_t::xrecv (zmq_msg_t *msg_, int flags_)
{
    //  Deallocate old content of the message.
    int rc = zmq_msg_close (msg_);
    zmq_assert (rc == 0);

    //  If request wasn't send, we can't wait for reply.
    if (!receiving_reply) {
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

    //  If we are starting to receive new reply, check whether prefix
    //  is well-formed and drop it.
    if (!more) {
        zmq_assert (msg_->flags & ZMQ_MSG_MORE);
        zmq_assert (zmq_msg_size (msg_) == 0);
        rc = zmq_msg_close (msg_);
        zmq_assert (rc == 0);

        //  Get the actual reply.
        bool recvd = reply_pipe->read (msg_);
        zmq_assert (recvd);
    }

    //  If this was last part of the reply, switch to request phase.
    more = msg_->flags & ZMQ_MSG_MORE;
    if (!more) {
        receiving_reply = false;
        reply_pipe = NULL;
    }

    return 0;
}

bool zmq::req_t::xhas_in ()
{
    if (receiving_reply && more)
        return true;

    if (!receiving_reply || !reply_pipe_active)
        return false;

    zmq_assert (reply_pipe);    
    if (!reply_pipe->check_read ()) {
        reply_pipe_active = false;
        return false;
    }

    return true;
}

bool zmq::req_t::xhas_out ()
{
    if (!receiving_reply && more)
        return true;

    if (receiving_reply)
        return false;

    while (active > 0) {
        if (out_pipes [current]->check_write ())
            return true;;

        active--;
        if (current < active) {
            in_pipes.swap (current, active);
            out_pipes.swap (current, active);
        }
        else
            current = 0;
    }

    return false;
}


