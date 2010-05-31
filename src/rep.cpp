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

#include "rep.hpp"
#include "err.hpp"
#include "pipe.hpp"

zmq::rep_t::rep_t (class app_thread_t *parent_) :
    socket_base_t (parent_),
    active (0),
    current (0),
    sending_reply (false),
    more (false),
    reply_pipe (NULL)
{
    options.requires_in = true;
    options.requires_out = true;

    //  We don't need immediate connect. We'll be able to send messages
    //  (replies) only when connection is established and thus requests
    //  can arrive anyway.
    options.immediate_connect = false;
}

zmq::rep_t::~rep_t ()
{
}

void zmq::rep_t::xattach_pipes (class reader_t *inpipe_,
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

void zmq::rep_t::xdetach_inpipe (class reader_t *pipe_)
{
    zmq_assert (sending_reply || !more || in_pipes [current] != pipe_);

    zmq_assert (pipe_);
    zmq_assert (in_pipes.size () == out_pipes.size ());

    in_pipes_t::size_type index = in_pipes.index (pipe_);

    if (index < active) {
        active--;
        if (current == active)
            current = 0;
    }

    if (out_pipes [index])
        out_pipes [index]->term ();
    in_pipes.erase (index);
    out_pipes.erase (index);
}

void zmq::rep_t::xdetach_outpipe (class writer_t *pipe_)
{
    zmq_assert (pipe_);
    zmq_assert (in_pipes.size () == out_pipes.size ());

    out_pipes_t::size_type index = out_pipes.index (pipe_);

    //  If the connection we've got the request from disconnects,
    //  there's nowhere to send the reply. Forget about the reply pipe.
    //  Once the reply is sent it will be dropped.
    if (sending_reply && pipe_ == reply_pipe)
        reply_pipe = NULL;

    if (out_pipes.index (pipe_) < active) {
        active--;
        if (current == active)
            current = 0;
    }

    if (in_pipes [index])
        in_pipes [index]->term ();
    in_pipes.erase (index);
    out_pipes.erase (index);
}

void zmq::rep_t::xkill (class reader_t *pipe_)
{
    //  Move the pipe to the list of inactive pipes.
    in_pipes_t::size_type index = in_pipes.index (pipe_);
    active--;
    in_pipes.swap (index, active);
    out_pipes.swap (index, active);
}

void zmq::rep_t::xrevive (class reader_t *pipe_)
{
    //  Move the pipe to the list of active pipes.
    in_pipes_t::size_type index = in_pipes.index (pipe_);
    in_pipes.swap (index, active);
    out_pipes.swap (index, active);
    active++;
}

void zmq::rep_t::xrevive (class writer_t *pipe_)
{
}

int zmq::rep_t::xsetsockopt (int option_, const void *optval_,
    size_t optvallen_)
{
    errno = EINVAL;
    return -1;
}

int zmq::rep_t::xsend (zmq_msg_t *msg_, int flags_)
{
    if (!sending_reply) {
        errno = EFSM;
        return -1;
    }

    if (reply_pipe) {

        // Push message to the reply pipe.
        bool written = reply_pipe->write (msg_);
        zmq_assert (!more || written);

        // The pipe is full...
        // When this happens, we simply return an error.
        // This makes REP sockets vulnerable to DoS attack when
        // misbehaving requesters stop collecting replies.
        // TODO: Tear down the underlying connection (?)
        if (!written) {
            errno = EAGAIN;
            return -1;
        }

        more = msg_->flags & ZMQ_MSG_MORE;
    }
    else {

        // If the requester have disconnected in the meantime, drop the reply.
        more = msg_->flags & ZMQ_MSG_MORE;
        zmq_msg_close (msg_);
    }

    // Flush the reply to the requester.
    if (!more) {
        if (reply_pipe)
            reply_pipe->flush ();
        sending_reply = false;
        reply_pipe = NULL;
    }

    // Detach the message from the data buffer.
    int rc = zmq_msg_init (msg_);
    zmq_assert (rc == 0);

    return 0;
}

int zmq::rep_t::xrecv (zmq_msg_t *msg_, int flags_)
{
    //  If we are in middle of sending a reply, we cannot receive next request.
    if (sending_reply) {
        errno = EFSM;
        return -1;
    }

    //  Deallocate old content of the message.
    zmq_msg_close (msg_);

    //  We haven't started reading a request yet...
    if (!more) {

        //  Round-robin over the pipes to get next message.
        int count;
        for (count = active; count != 0; count--) {
            if (in_pipes [current]->read (msg_))
                break;
            current++;
            if (current >= active)
                current = 0;
        }

        //  No message is available. Initialise the output parameter
        //  to be a 0-byte message.
        if (count == 0) {
            zmq_msg_init (msg_);
            errno = EAGAIN;
            return -1;
        }

        //  We are aware of a new message now. Setup the reply pipe.
        reply_pipe = out_pipes [current];

        //  Copy the routing info to the reply pipe.
        while (true) {

            //  Push message to the reply pipe.
            //  TODO: What if the pipe is full?
            //  Tear down the underlying connection?
            bool written = reply_pipe->write (msg_);
            zmq_assert (written);

            //  Message part of zero size delimits the traceback stack.
            if (zmq_msg_size (msg_) == 0)
                break;

            //  Get next part of the message.
            bool fetched = in_pipes [current]->read (msg_);
            zmq_assert (fetched);
        }
    }

    //  Now the routing info is processed. Get the first part
    //  of the message payload and exit.
    bool fetched = in_pipes [current]->read (msg_);
    zmq_assert (fetched);
    more = msg_->flags & ZMQ_MSG_MORE;
    if (!more) {
        current++;
        if (current >= active)
            current = 0;
        sending_reply = true;
    }
    return 0;
}

bool zmq::rep_t::xhas_in ()
{
    if (sending_reply)
        return false;

    if (more)
        return true;

    for (int count = active; count != 0; count--) {
        if (in_pipes [current]->check_read ())
            return !sending_reply;
        current++;
        if (current >= active)
            current = 0;
    }

    return false;
}

bool zmq::rep_t::xhas_out ()
{
    if (!sending_reply)
        return false;

    if (more)
        return true;

    //  TODO: No check for write here...
    return sending_reply;
}

