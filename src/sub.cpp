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

#include "sub.hpp"
#include "msg.hpp"

zmq::sub_t::sub_t (class ctx_t *parent_, uint32_t tid_) :
    xsub_t (parent_, tid_),
    has_message (false),
    more (false)
{
    options.type = ZMQ_SUB;
    int rc = message.init ();
    errno_assert (rc == 0);
}

zmq::sub_t::~sub_t ()
{
    int rc = message.close ();
    errno_assert (rc == 0);
}

int zmq::sub_t::xsetsockopt (int option_, const void *optval_,
    size_t optvallen_)
{
    //  Process a subscription.
    if (option_ == ZMQ_SUBSCRIBE)
        subscriptions.add ((unsigned char*) optval_, optvallen_);

    //  Process an unsubscription. Return error if there is no corresponding
    //  subscription.
    else if (option_ == ZMQ_UNSUBSCRIBE) {
        if (!subscriptions.rm ((unsigned char*) optval_, optvallen_)) {
            errno = EINVAL;
            return -1;
        }
    }

    //  Unknow option.
    else {
        errno = EINVAL;
        return -1;
    }

    //  Create the subscription message.
    msg_t msg;
    int rc = msg.init_size (optvallen_ + 1);
    errno_assert (rc == 0);
    unsigned char *data = (unsigned char*) msg.data ();
    if (option_ == ZMQ_SUBSCRIBE)
        *data = 1;
    else if (option_ == ZMQ_UNSUBSCRIBE)
        *data = 0;
    memcpy (data + 1, optval_, optvallen_);

    //  Pass it further on in the stack.
    int err = 0;
    rc = xsub_t::xsend (&msg, 0);
    if (rc != 0)
        err = errno;
    int rc2 = msg.close ();
    errno_assert (rc2 == 0);
    if (rc != 0)
        errno = err;
    return rc;
}

int zmq::sub_t::xsend (msg_t *msg_, int options_)
{
    //  Overload the XSUB's send.
    errno = ENOTSUP;
    return -1;
}

bool zmq::sub_t::xhas_out ()
{
    //  Overload the XSUB's send.
    return false;
}

int zmq::sub_t::xrecv (msg_t *msg_, int flags_)
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
        int rc = xsub_t::xrecv (msg_, flags_);

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
            rc = xsub_t::xrecv (msg_, ZMQ_DONTWAIT);
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
        int rc = xsub_t::xrecv (&message, ZMQ_DONTWAIT);

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
            rc = xsub_t::xrecv (&message, ZMQ_DONTWAIT);
            zmq_assert (rc == 0);
        }
    }
}

bool zmq::sub_t::match (msg_t *msg_)
{
    return subscriptions.check ((unsigned char*) msg_->data (), msg_->size ());
}

