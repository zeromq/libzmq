/*
    Copyright (c) 2007-2010 iMatix Corporation

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <string.h>

#include "../include/zmq.h"

#include "sub.hpp"
#include "err.hpp"

zmq::sub_t::sub_t (class ctx_t *parent_, uint32_t tid_) :
    socket_base_t (parent_, tid_),
    fq (this),
    has_message (false),
    more (false)
{
    options.type = ZMQ_SUB;
    options.requires_in = true;
    options.requires_out = false;
    zmq_msg_init (&message);
}

zmq::sub_t::~sub_t ()
{
    zmq_msg_close (&message);
}

void zmq::sub_t::xattach_pipes (class reader_t *inpipe_,
    class writer_t *outpipe_, const blob_t &peer_identity_)
{
    zmq_assert (inpipe_ && !outpipe_);
    fq.attach (inpipe_);
}

void zmq::sub_t::process_term (int linger_)
{
    fq.terminate ();
    socket_base_t::process_term (linger_);
}

int zmq::sub_t::xsetsockopt (int option_, const void *optval_,
    size_t optvallen_)
{
    if (option_ == ZMQ_SUBSCRIBE) {
        subscriptions.add ((unsigned char*) optval_, optvallen_);
        return 0;
    }
    
    if (option_ == ZMQ_UNSUBSCRIBE) {
        if (!subscriptions.rm ((unsigned char*) optval_, optvallen_)) {
            errno = EINVAL;
            return -1;
        }
        return 0;
    }

    errno = EINVAL;
    return -1;
}

int zmq::sub_t::xrecv (zmq_msg_t *msg_, int flags_)
{
    //  If there's already a message prepared by a previous call to zmq_poll,
    //  return it straight ahead.
    if (has_message) {
        zmq_msg_move (msg_, &message);
        has_message = false;
        more = msg_->flags & ZMQ_MSG_MORE;
        return 0;
    }

    //  TODO: This can result in infinite loop in the case of continuous
    //  stream of non-matching messages which breaks the non-blocking recv
    //  semantics.
    while (true) {

        //  Get a message using fair queueing algorithm.
        int rc = fq.recv (msg_, flags_);

        //  If there's no message available, return immediately.
        //  The same when error occurs.
        if (rc != 0)
            return -1;

        //  Check whether the message matches at least one subscription.
        //  Non-initial parts of the message are passed 
        if (more || match (msg_)) {
            more = msg_->flags & ZMQ_MSG_MORE;
            return 0;
        }

        //  Message doesn't match. Pop any remaining parts of the message
        //  from the pipe.
        while (msg_->flags & ZMQ_MSG_MORE) {
            rc = fq.recv (msg_, ZMQ_NOBLOCK);
            zmq_assert (rc == 0);
        }
    }
}

bool zmq::sub_t::xhas_in ()
{
    //  There are subsequent parts of the partly-read message available.
    if (more)
        return true;

    //  If there's already a message prepared by a previous call to zmq_poll,
    //  return straight ahead.
    if (has_message)
        return true;

    //  TODO: This can result in infinite loop in the case of continuous
    //  stream of non-matching messages.
    while (true) {

        //  Get a message using fair queueing algorithm.
        int rc = fq.recv (&message, ZMQ_NOBLOCK);

        //  If there's no message available, return immediately.
        //  The same when error occurs.
        if (rc != 0) {
            zmq_assert (errno == EAGAIN);
            return false;
        }

        //  Check whether the message matches at least one subscription.
        if (match (&message)) {
            has_message = true;
            return true;
        }

        //  Message doesn't match. Pop any remaining parts of the message
        //  from the pipe.
        while (message.flags & ZMQ_MSG_MORE) {
            rc = fq.recv (&message, ZMQ_NOBLOCK);
            zmq_assert (rc == 0);
        }
    }
}

bool zmq::sub_t::match (zmq_msg_t *msg_)
{
    return subscriptions.check ((unsigned char*) zmq_msg_data (msg_),
        zmq_msg_size (msg_));
}
