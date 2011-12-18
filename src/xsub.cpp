/*
    Copyright (c) 2010-2011 250bpm s.r.o.
    Copyright (c) 2011 VMware, Inc.
    Copyright (c) 2010-2011 Other contributors as noted in the AUTHORS file

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
    has_message (false),
    more (false)
{
    options.type = ZMQ_XSUB;

    //  When socket is being closed down we don't want to wait till pending
    //  subscription commands are sent to the wire.
    options.linger = 0;

    int rc = message.init ();
    errno_assert (rc == 0);
}

zmq::xsub_t::~xsub_t ()
{
    int rc = message.close ();
    errno_assert (rc == 0);
}

void zmq::xsub_t::xattach_pipe (pipe_t *pipe_)
{
    zmq_assert (pipe_);
    fq.attach (pipe_);
    dist.attach (pipe_);

    //  Send all the cached subscriptions to the new upstream peer.
    subscriptions.apply (send_subscription, pipe_);
    pipe_->flush ();
}

void zmq::xsub_t::xread_activated (pipe_t *pipe_)
{
    fq.activated (pipe_);
}

void zmq::xsub_t::xwrite_activated (pipe_t *pipe_)
{
    dist.activated (pipe_);
}

void zmq::xsub_t::xterminated (pipe_t *pipe_)
{
    fq.terminated (pipe_);
    dist.terminated (pipe_);
}

void zmq::xsub_t::xhiccuped (pipe_t *pipe_)
{
    //  Send all the cached subscriptions to the hiccuped pipe.
    subscriptions.apply (send_subscription, pipe_);
    pipe_->flush ();
}

int zmq::xsub_t::xsend (msg_t *msg_, int flags_)
{
    size_t size = msg_->size ();
    unsigned char *data = (unsigned char*) msg_->data ();

    // Malformed subscriptions.
    if (size < 1 || (*data != 0 && *data != 1)) {
        errno = EINVAL;
        return -1;
    }

    // Process the subscription.
    if (*data == 1) {
        if (subscriptions.add (data + 1, size - 1))
            return dist.send_to_all (msg_, flags_);
        else
            return 0;
    }
    else if (*data == 0) {
        if (subscriptions.rm (data + 1, size - 1))
            return dist.send_to_all (msg_, flags_);
        else
            return 0;
    }

    zmq_assert (false);
    return -1;
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
        more = msg_->flags () & msg_t::more ? true : false;
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
        if (more || !options.filter || match (msg_)) {
            more = msg_->flags () & msg_t::more ? true : false;
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
        if (!options.filter || match (&message)) {
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

void zmq::xsub_t::send_subscription (unsigned char *data_, size_t size_,
    void *arg_)
{
    pipe_t *pipe = (pipe_t*) arg_;

    //  Create the subsctription message.
    msg_t msg;
    int rc = msg.init_size (size_ + 1);
    zmq_assert (rc == 0);
    unsigned char *data = (unsigned char*) msg.data ();
    data [0] = 1;
    memcpy (data + 1, data_, size_);

    //  Send it to the pipe.
    bool sent = pipe->write (&msg);
    zmq_assert (sent);
}

zmq::xsub_session_t::xsub_session_t (io_thread_t *io_thread_, bool connect_,
      socket_base_t *socket_, const options_t &options_,
      const char *protocol_, const char *address_) :
    session_base_t (io_thread_, connect_, socket_, options_, protocol_,
        address_)
{
}

zmq::xsub_session_t::~xsub_session_t ()
{
}

