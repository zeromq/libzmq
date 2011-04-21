/*
    Copyright (c) 2007-2011 iMatix Corporation
    Copyright (c) 2007-2011 Other contributors as noted in the AUTHORS file

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

#include "xsub.hpp"
#include "err.hpp"

zmq::xsub_t::xsub_t (class ctx_t *parent_, uint32_t tid_) :
    socket_base_t (parent_, tid_),
    fq (this),
    has_message (false),
    more (false)
{
    options.type = ZMQ_XSUB;
    options.requires_in = true;
    options.requires_out = false;
    int rc = message.init ();
    errno_assert (rc == 0);
}

zmq::xsub_t::~xsub_t ()
{
    int rc = message.close ();
    errno_assert (rc == 0);
}

void zmq::xsub_t::xattach_pipes (class reader_t *inpipe_,
    class writer_t *outpipe_, const blob_t &peer_identity_)
{
    zmq_assert (inpipe_ && !outpipe_);
    fq.attach (inpipe_);
}

void zmq::xsub_t::process_term (int linger_)
{
    fq.terminate ();
    socket_base_t::process_term (linger_);
}

int zmq::xsub_t::xsend (msg_t *msg_, int options_)
{
    size_t size = msg_->size ();
    unsigned char *data = (unsigned char*) msg_->data ();

    //  Malformed subscriptions are dropped silently.
    if (size >= 1) {

        //  Process a subscription.
        if (*data == 1)
            subscriptions.add (data + 1, size - 1);

        //  Process an unsubscription. Invalid unsubscription is ignored.
        if (*data == 0)
            subscriptions.rm (data + 1, size - 1);
    }

    int rc = msg_->close ();
    errno_assert (rc == 0);
    rc = msg_->init ();
    errno_assert (rc == 0);
    return 0;
}

bool zmq::xsub_t::xhas_out ()
{
    //  Subscription can be added/removed anytime.
    return true;
}

int zmq::xsub_t::xrecv (msg_t *msg_, int flags_)
{
    //  If there's already a message prepared by a previous call to zmq_poll,
    //  return it straight ahead.
    if (has_message) {
        int rc = msg_->move (message);
        errno_assert (rc == 0);
        has_message = false;
        more = msg_->flags () & msg_t::more;
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
            more = msg_->flags () & msg_t::more;
            return 0;
        }

        //  Message doesn't match. Pop any remaining parts of the message
        //  from the pipe.
        while (msg_->flags () & msg_t::more) {
            rc = fq.recv (msg_, ZMQ_DONTWAIT);
            zmq_assert (rc == 0);
        }
    }
}

bool zmq::xsub_t::xhas_in ()
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
        int rc = fq.recv (&message, ZMQ_DONTWAIT);

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
        while (message.flags () & msg_t::more) {
            rc = fq.recv (&message, ZMQ_DONTWAIT);
            zmq_assert (rc == 0);
        }
    }
}

bool zmq::xsub_t::match (msg_t *msg_)
{
    return subscriptions.check ((unsigned char*) msg_->data (), msg_->size ());
}

