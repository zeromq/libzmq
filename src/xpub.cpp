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

#include "xpub.hpp"
#include "pipe.hpp"
#include "err.hpp"
#include "msg.hpp"

zmq::xpub_t::xpub_t (class ctx_t *parent_, uint32_t tid_, int sid_) :
    socket_base_t (parent_, tid_, sid_),
    verbose(false),
    more (false)
{
    options.type = ZMQ_XPUB;
}

zmq::xpub_t::~xpub_t ()
{
}

void zmq::xpub_t::xattach_pipe (pipe_t *pipe_, bool icanhasall_)
{
    zmq_assert (pipe_);
    dist.attach (pipe_);

    //  If icanhasall_ is specified, the caller would like to subscribe
    //  to all data on this pipe, implicitly.
    if (icanhasall_)
        subscriptions.add (NULL, 0, pipe_);

    //  The pipe is active when attached. Let's read the subscriptions from
    //  it, if any.
    xread_activated (pipe_);
}

void zmq::xpub_t::xread_activated (pipe_t *pipe_)
{
    //  There are some subscriptions waiting. Let's process them.
    msg_t sub;
    while (pipe_->read (&sub)) {

        //  Apply the subscription to the trie.
        unsigned char *const data = (unsigned char*) sub.data ();
        const size_t size = sub.size ();
        if (size > 0 && (*data == 0 || *data == 1)) {
            bool unique;
            if (*data == 0)
                unique = subscriptions.rm (data + 1, size - 1, pipe_);
            else
                unique = subscriptions.add (data + 1, size - 1, pipe_);

            //  If the subscription is not a duplicate store it so that it can be
            //  passed to used on next recv call. (Unsubscribe is not verbose.)
            if (options.type == ZMQ_XPUB && (unique || (*data && verbose)))
                pending.push_back (blob_t (data, size));
        }

        sub.close ();
    }
}

void zmq::xpub_t::xwrite_activated (pipe_t *pipe_)
{
    dist.activated (pipe_);
}

int zmq::xpub_t::xsetsockopt (int option_, const void *optval_,
    size_t optvallen_)
{
    if (option_ != ZMQ_XPUB_VERBOSE) {
        errno = EINVAL;
        return -1;
    }
    if (optvallen_ != sizeof (int) || *static_cast <const int*> (optval_) < 0) {
        errno = EINVAL;
        return -1;
    }
    verbose = *static_cast <const int*> (optval_);
    return 0;
}

void zmq::xpub_t::xterminated (pipe_t *pipe_)
{
    //  Remove the pipe from the trie. If there are topics that nobody
    //  is interested in anymore, send corresponding unsubscriptions
    //  upstream.
    subscriptions.rm (pipe_, send_unsubscription, this);

    dist.terminated (pipe_);
}

void zmq::xpub_t::mark_as_matching (pipe_t *pipe_, void *arg_)
{
    xpub_t *self = (xpub_t*) arg_;
    self->dist.match (pipe_);
}

int zmq::xpub_t::xsend (msg_t *msg_, int flags_)
{
    bool msg_more = msg_->flags () & msg_t::more ? true : false;

    //  For the first part of multi-part message, find the matching pipes.
    if (!more)
        subscriptions.match ((unsigned char*) msg_->data (), msg_->size (),
            mark_as_matching, this);

    //  Send the message to all the pipes that were marked as matching
    //  in the previous step.
    int rc = dist.send_to_matching (msg_, flags_);
    if (rc != 0)
        return rc;

    //  If we are at the end of multi-part message we can mark all the pipes
    //  as non-matching.
    if (!msg_more)
        dist.unmatch ();

    more = msg_more;

    return 0;
}

bool zmq::xpub_t::xhas_out ()
{
    return dist.has_out ();
}

int zmq::xpub_t::xrecv (msg_t *msg_, int flags_)
{
    // flags_ is unused
    (void)flags_;

    //  If there is at least one 
    if (pending.empty ()) {
        errno = EAGAIN;
        return -1;
    }

    int rc = msg_->close ();
    errno_assert (rc == 0);
    rc = msg_->init_size (pending.front ().size ());
    errno_assert (rc == 0);
    memcpy (msg_->data (), pending.front ().data (),
        pending.front ().size ());
    pending.pop_front ();
    return 0;
}

bool zmq::xpub_t::xhas_in ()
{
    return !pending.empty ();
}

void zmq::xpub_t::send_unsubscription (unsigned char *data_, size_t size_,
    void *arg_)
{
    xpub_t *self = (xpub_t*) arg_;

    if (self->options.type != ZMQ_PUB) {

		//  Place the unsubscription to the queue of pending (un)sunscriptions
		//  to be retrived by the user later on.
		blob_t unsub (size_ + 1, 0);
		unsub [0] = 0;
		memcpy (&unsub [1], data_, size_);
		self->pending.push_back (unsub);
    }
}

zmq::xpub_session_t::xpub_session_t (io_thread_t *io_thread_, bool connect_,
      socket_base_t *socket_, const options_t &options_,
      const address_t *addr_) :
    session_base_t (io_thread_, connect_, socket_, options_, addr_)
{
}

zmq::xpub_session_t::~xpub_session_t ()
{
}

