/*
    Copyright (c) 2007-2016 Contributors as noted in the AUTHORS file

    This file is part of libzmq, the ZeroMQ core engine in C++.

    libzmq is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License (LGPL) as published
    by the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    As a special exception, the Contributors give you permission to link
    this library with independent modules to produce an executable,
    regardless of the license terms of these independent modules, and to
    copy and distribute the resulting executable under terms of your choice,
    provided that you also meet, for each linked independent module, the
    terms and conditions of the license of that module. An independent
    module is a module which is not derived from or based on this library.
    If you modify this library, you must extend this exception to your
    version of the library.

    libzmq is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
    FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
    License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "precompiled.hpp"
#include <string.h>

#include "macros.hpp"
#include "xsub.hpp"
#include "err.hpp"

zmq::xsub_t::xsub_t (class ctx_t *parent_, uint32_t tid_, int sid_) :
    socket_base_t (parent_, tid_, sid_),
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

void zmq::xsub_t::xattach_pipe (pipe_t *pipe_, bool subscribe_to_all_)
{
    LIBZMQ_UNUSED (subscribe_to_all_);

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

void zmq::xsub_t::xpipe_terminated (pipe_t *pipe_)
{
    fq.pipe_terminated (pipe_);
    dist.pipe_terminated (pipe_);
}

void zmq::xsub_t::xhiccuped (pipe_t *pipe_)
{
    //  Send all the cached subscriptions to the hiccuped pipe.
    subscriptions.apply (send_subscription, pipe_);
    pipe_->flush ();
}

int zmq::xsub_t::xsend (msg_t *msg_)
{
    size_t size = msg_->size ();
    unsigned char *data = (unsigned char *) msg_->data ();

    if (size > 0 && *data == 1) {
        //  Process subscribe message
        //  This used to filter out duplicate subscriptions,
        //  however this is alread done on the XPUB side and
        //  doing it here as well breaks ZMQ_XPUB_VERBOSE
        //  when there are forwarding devices involved.
        subscriptions.add (data + 1, size - 1);
        return dist.send_to_all (msg_);
    }
    else
    if (size > 0 && *data == 0) {
        //  Process unsubscribe message
        if (subscriptions.rm (data + 1, size - 1))
            return dist.send_to_all (msg_);
    }
    else
        //  User message sent upstream to XPUB socket
        return dist.send_to_all (msg_);

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

int zmq::xsub_t::xrecv (msg_t *msg_)
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
        int rc = fq.recv (msg_);

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
            rc = fq.recv (msg_);
            errno_assert (rc == 0);
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
        int rc = fq.recv (&message);

        //  If there's no message available, return immediately.
        //  The same when error occurs.
        if (rc != 0) {
            errno_assert (errno == EAGAIN);
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
            rc = fq.recv (&message);
            errno_assert (rc == 0);
        }
    }
}

const zmq::blob_t &zmq::xsub_t::get_credential () const
{
    return fq.get_credential ();
}

bool zmq::xsub_t::match (msg_t *msg_)
{
    bool matching = subscriptions.check ((unsigned char*) msg_->data (), msg_->size ());

    return matching ^ options.invert_matching;
}

void zmq::xsub_t::send_subscription (unsigned char *data_, size_t size_,
    void *arg_)
{
    pipe_t *pipe = (pipe_t*) arg_;

    //  Create the subscription message.
    msg_t msg;
    int rc = msg.init_size (size_ + 1);
    errno_assert (rc == 0);
    unsigned char *data = (unsigned char*) msg.data ();
    data [0] = 1;

    //  We explicitly allow a NULL subscription with size zero
    if (size_) {
        assert (data_);
        memcpy (data + 1, data_, size_);
    }

    //  Send it to the pipe.
    bool sent = pipe->write (&msg);
    //  If we reached the SNDHWM, and thus cannot send the subscription, drop
    //  the subscription message instead. This matches the behaviour of
    //  zmq_setsockopt(ZMQ_SUBSCRIBE, ...), which also drops subscriptions
    //  when the SNDHWM is reached.
    if (!sent)
        msg.close ();
}
