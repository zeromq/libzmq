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

#include "xpub.hpp"
#include "pipe.hpp"
#include "err.hpp"
#include "msg.hpp"
#include "macros.hpp"

zmq::xpub_t::xpub_t (class ctx_t *parent_, uint32_t tid_, int sid_) :
    socket_base_t (parent_, tid_, sid_),
    verbose_subs (false),
    verbose_unsubs (false),
    more (false),
    lossy (true),
    manual (false),
    pending_pipes (),
    welcome_msg ()
{
    last_pipe = NULL;
    options.type = ZMQ_XPUB;
    welcome_msg.init ();
}

zmq::xpub_t::~xpub_t ()
{
    welcome_msg.close ();
}

void zmq::xpub_t::xattach_pipe (pipe_t *pipe_, bool subscribe_to_all_)
{
    zmq_assert (pipe_);
    dist.attach (pipe_);

    //  If subscribe_to_all_ is specified, the caller would like to subscribe
    //  to all data on this pipe, implicitly.
    if (subscribe_to_all_)
        subscriptions.add (NULL, 0, pipe_);

    // if welcome message exists, send a copy of it
    if (welcome_msg.size () > 0)
    {
        msg_t copy;
        copy.init ();
        int rc = copy.copy (welcome_msg);
        errno_assert (rc == 0);
        bool ok = pipe_->write (&copy);
        zmq_assert (ok);
        pipe_->flush ();
    }

    //  The pipe is active when attached. Let's read the subscriptions from
    //  it, if any.
    xread_activated (pipe_);
}

void zmq::xpub_t::xread_activated (pipe_t *pipe_)
{
    //  There are some subscriptions waiting. Let's process them.
    msg_t sub;
    while (pipe_->read (&sub)) {
        //  Apply the subscription to the trie
        unsigned char *const data = (unsigned char *) sub.data ();
        const size_t size = sub.size ();
        metadata_t* metadata = sub.metadata();
        if (size > 0 && (*data == 0 || *data == 1)) {
            if (manual)
            {
                // Store manual subscription to use on termination
                if (*data == 0)
                    manual_subscriptions.rm (data + 1, size - 1, pipe_);
                else
                    manual_subscriptions.add (data + 1, size - 1, pipe_);

                pending_pipes.push_back (pipe_);
                pending_data.push_back (blob_t (data, size));
                if (metadata)
                    metadata->add_ref ();
                pending_metadata.push_back (metadata);
                pending_flags.push_back (0);
            }
            else
            {
                bool unique;
                if (*data == 0)
                    unique = subscriptions.rm (data + 1, size - 1, pipe_);
                else
                    unique = subscriptions.add (data + 1, size - 1, pipe_);

                //  If the (un)subscription is not a duplicate store it so that it can be
                //  passed to the user on next recv call unless verbose mode is enabled
                //  which makes to pass always these messages.
                if (options.type == ZMQ_XPUB && (unique || (*data == 1 && verbose_subs) ||
                        (*data == 0 && verbose_unsubs && verbose_subs))) {
                    pending_data.push_back (blob_t(data, size));
                    if (metadata)
                        metadata->add_ref ();
                    pending_metadata.push_back (metadata);
                    pending_flags.push_back (0);
                }
            }
        }
        else {
            //  Process user message coming upstream from xsub socket
            pending_data.push_back (blob_t (data, size));
            if (metadata)
                metadata->add_ref ();
            pending_metadata.push_back (metadata);
            pending_flags.push_back (sub.flags ());
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
    if (option_ == ZMQ_XPUB_VERBOSE
     || option_ == ZMQ_XPUB_VERBOSER
     || option_ == ZMQ_XPUB_NODROP
     || option_ == ZMQ_XPUB_MANUAL) {
        if (optvallen_ != sizeof (int) || *static_cast <const int*> (optval_) < 0) {
            errno = EINVAL;
            return -1;
        }
        if (option_ == ZMQ_XPUB_VERBOSE) {
            verbose_subs = (*static_cast <const int*> (optval_) != 0);
            verbose_unsubs = 0;
        }
        else
        if (option_ == ZMQ_XPUB_VERBOSER) {
            verbose_subs = (*static_cast <const int*> (optval_) != 0);
            verbose_unsubs = verbose_subs;
        }
        else
        if (option_ == ZMQ_XPUB_NODROP)
            lossy = (*static_cast <const int*> (optval_) == 0);
        else
        if (option_ == ZMQ_XPUB_MANUAL)
            manual = (*static_cast <const int*> (optval_) != 0);
    }
    else
    if (option_ == ZMQ_SUBSCRIBE && manual) {
        if (last_pipe != NULL)
            subscriptions.add ((unsigned char *) optval_, optvallen_, last_pipe);
    }
    else
    if (option_ == ZMQ_UNSUBSCRIBE && manual) {
        if (last_pipe != NULL)
            subscriptions.rm ((unsigned char *) optval_, optvallen_, last_pipe);
    }
    else
    if (option_ == ZMQ_XPUB_WELCOME_MSG) {
        welcome_msg.close ();

        if (optvallen_ > 0) {
            int rc = welcome_msg.init_size (optvallen_);
            errno_assert(rc == 0);

            unsigned char *data = (unsigned char*) welcome_msg.data ();
            memcpy (data, optval_, optvallen_);
        }
        else
            welcome_msg.init ();
    }
    else {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

static void stub (unsigned char *data_, size_t size_, void *arg_)
{
    LIBZMQ_UNUSED(data_);
    LIBZMQ_UNUSED(size_);
    LIBZMQ_UNUSED(arg_);
}

void zmq::xpub_t::xpipe_terminated (pipe_t *pipe_)
{
    if (manual)
    {
        //  Remove the pipe from the trie and send corresponding manual
        //  unsubscriptions upstream.
        manual_subscriptions.rm (pipe_, send_unsubscription, this, false);
        //  Remove pipe without actually sending the message as it was taken
        //  care of by the manual call above. subscriptions is the real mtrie,
        //  so the pipe must be removed from there or it will be left over.
        subscriptions.rm (pipe_, stub, NULL, false);
    }
    else
    {
        //  Remove the pipe from the trie. If there are topics that nobody
        //  is interested in anymore, send corresponding unsubscriptions
        //  upstream.
        subscriptions.rm (pipe_, send_unsubscription, this, !verbose_unsubs);
    }

    dist.pipe_terminated (pipe_);
}

void zmq::xpub_t::mark_as_matching (pipe_t *pipe_, void *arg_)
{
    xpub_t *self = (xpub_t*) arg_;
    self->dist.match (pipe_);
}

int zmq::xpub_t::xsend (msg_t *msg_)
{
    bool msg_more = msg_->flags () & msg_t::more ? true : false;

    //  For the first part of multi-part message, find the matching pipes.
    if (!more) {
        subscriptions.match ((unsigned char*) msg_->data (), msg_->size (),
            mark_as_matching, this);
        // If inverted matching is used, reverse the selection now
        if (options.invert_matching) {
            dist.reverse_match();
        }
    }

    int rc = -1;            //  Assume we fail
    if (lossy || dist.check_hwm ()) {
        if (dist.send_to_matching (msg_) == 0) {
            //  If we are at the end of multi-part message we can mark
            //  all the pipes as non-matching.
            if (!msg_more)
                dist.unmatch ();
            more = msg_more;
            rc = 0;         //  Yay, sent successfully
        }
    }
    else
        errno = EAGAIN;
    return rc;
}

bool zmq::xpub_t::xhas_out ()
{
    return dist.has_out ();
}

int zmq::xpub_t::xrecv (msg_t *msg_)
{
    //  If there is at least one
    if (pending_data.empty ()) {
        errno = EAGAIN;
        return -1;
    }

    // User is reading a message, set last_pipe and remove it from the deque
    if (manual && !pending_pipes.empty ()) {
        last_pipe = pending_pipes.front ();
        pending_pipes.pop_front ();
    }

    int rc = msg_->close ();
    errno_assert (rc == 0);
    rc = msg_->init_size (pending_data.front ().size ());
    errno_assert (rc == 0);
    memcpy (msg_->data (),
        pending_data.front ().data (),
        pending_data.front ().size ());

    // set metadata only if there is some
    if (metadata_t* metadata = pending_metadata.front ()) {
        msg_->set_metadata (metadata);
        // Remove ref corresponding to vector placement
        metadata->drop_ref();
    }

    msg_->set_flags (pending_flags.front ());
    pending_data.pop_front ();
    pending_metadata.pop_front ();
    pending_flags.pop_front ();
    return 0;
}

bool zmq::xpub_t::xhas_in ()
{
    return !pending_data.empty ();
}

void zmq::xpub_t::send_unsubscription (unsigned char *data_, size_t size_,
    void *arg_)
{
    xpub_t *self = (xpub_t*) arg_;

    if (self->options.type != ZMQ_PUB) {
        //  Place the unsubscription to the queue of pending (un)subscriptions
        //  to be retrieved by the user later on.
        blob_t unsub (size_ + 1);
        *unsub.data() = 0;
        if (size_ > 0)
            memcpy (unsub.data() + 1, data_, size_);
        self->pending_data.ZMQ_PUSH_OR_EMPLACE_BACK (ZMQ_MOVE(unsub));
        self->pending_metadata.push_back (NULL);
        self->pending_flags.push_back (0);

        if (self->manual) {
            self->last_pipe = NULL;
            self->pending_pipes.push_back (NULL);
        }
    }
}
