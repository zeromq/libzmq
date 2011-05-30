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

#include "xpub.hpp"
#include "pipe.hpp"
#include "err.hpp"
#include "msg.hpp"

zmq::xpub_t::xpub_t (class ctx_t *parent_, uint32_t tid_) :
    socket_base_t (parent_, tid_)
{
    options.type = ZMQ_XPUB;
}

zmq::xpub_t::~xpub_t ()
{
}

void zmq::xpub_t::xattach_pipe (pipe_t *pipe_, const blob_t &peer_identity_)
{
    zmq_assert (pipe_);
    dist.attach (pipe_);
    fq.attach (pipe_);
}

void zmq::xpub_t::xread_activated (pipe_t *pipe_)
{
    fq.activated (pipe_);
}

void zmq::xpub_t::xwrite_activated (pipe_t *pipe_)
{
    dist.activated (pipe_);
}

void zmq::xpub_t::xterminated (pipe_t *pipe_)
{
    //  Remove the pipe from the trie. If there are topics that nobody
    //  is interested in anymore, send corresponding unsubscriptions
    //  upstream.
    subscriptions.rm (pipe_, send_unsubscription, this);

    dist.terminated (pipe_);
    fq.terminated (pipe_);
}

int zmq::xpub_t::xsend (msg_t *msg_, int flags_)
{
    //  First, process any (un)subscriptions from downstream.
    msg_t sub;
    sub.init ();
    while (true) {

        //  Grab next subscription.
        pipe_t *pipe;
        int rc = fq.recvpipe (&sub, 0, &pipe);
        if (rc != 0 && errno == EAGAIN)
            break;
        errno_assert (rc == 0);

        //  Apply the subscription to the trie. If it's not a duplicate,
        //  store it so that it can be passed to used on next recv call.
        if (apply_subscription (&sub, pipe) && options.type != ZMQ_PUB)
            pending.push_back (blob_t ((unsigned char*) sub.data (),
                sub.size ()));
    }
    sub.close ();
    
    return dist.send (msg_, flags_);
}

bool zmq::xpub_t::xhas_out ()
{
    return dist.has_out ();
}

int zmq::xpub_t::xrecv (msg_t *msg_, int flags_)
{
    //  If there is at least one 
    if (!pending.empty ()) {
        int rc = msg_->close ();
        errno_assert (rc == 0);
        rc = msg_->init_size (pending.front ().size ());
        errno_assert (rc == 0);
        memcpy (msg_->data (), pending.front ().data (),
            pending.front ().size ());
        pending.pop_front ();
        return 0;
    }

    //  Grab and apply next subscription.
    pipe_t *pipe;
    int rc = fq.recvpipe (msg_, 0, &pipe);
    if (rc != 0)
        return -1;
    if (!apply_subscription (msg_, pipe)) {
//  TODO: This should be a loop rather!
        msg_->close ();
        msg_->init ();
        errno = EAGAIN;
        return -1;
    }
    return 0;
}

bool zmq::xpub_t::xhas_in ()
{
    if (!pending.empty ())
        return true;

    //  Even if there are subscriptions in the fair-queuer they may be
    //  duplicates. Thus, we have to check by hand wheter there is any
    //  subscription available to pass upstream.
    //  First, process any (un)subscriptions from downstream.
    msg_t sub;
    sub.init ();
    while (true) {

        //  Grab next subscription.
        pipe_t *pipe;
        int rc = fq.recvpipe (&sub, 0, &pipe);
        if (rc != 0 && errno == EAGAIN) {
            sub.close ();
            return false;
        }
        errno_assert (rc == 0);

        //  Apply the subscription to the trie. If it's not a duplicate store
        //  it so that it can be passed to used on next recv call.
        if (apply_subscription (&sub, pipe) && options.type != ZMQ_PUB) {
            pending.push_back (blob_t ((unsigned char*) sub.data (),
                sub.size ()));
            sub.close ();
            return true;
        }
    }
}

bool zmq::xpub_t::apply_subscription (msg_t *sub_, pipe_t *pipe_)
{
    unsigned char *data = (unsigned char*) sub_->data ();
    size_t size = sub_->size ();
    zmq_assert (size > 0 && (*data == 0 || *data == 1));

    if (*data == 0)
        return subscriptions.rm (data + 1, size - 1, pipe_);
    else
        return subscriptions.add (data + 1, size - 1, pipe_);
}

void zmq::xpub_t::send_unsubscription (unsigned char *data_, size_t size_,
    void *arg_)
{
    xpub_t *self = (xpub_t*) arg_;

    if (self->options.type != ZMQ_PUB) {

		//  Place the unsubscription to the queue of pending (un)sunscriptions
		//  to be retrived by the user later on.
		xpub_t *self = (xpub_t*) arg_;
		blob_t unsub (size_ + 1, 0);
		unsub [0] = 0;
		memcpy (&unsub [1], data_, size_);
		self->pending.push_back (unsub);
    }
}

