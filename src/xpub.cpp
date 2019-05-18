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
#include "generic_mtrie_impl.hpp"

zmq::xpub_t::xpub_t (class ctx_t *parent_, uint32_t tid_, int sid_) :
    socket_base_t (parent_, tid_, sid_),
    _verbose_subs (false),
    _verbose_unsubs (false),
    _more (false),
    _lossy (true),
    _manual (false),
    _send_last_pipe (false),
    _pending_pipes (),
    _welcome_msg ()
{
    _last_pipe = NULL;
    options.type = ZMQ_XPUB;
    _welcome_msg.init ();
}

zmq::xpub_t::~xpub_t ()
{
    _welcome_msg.close ();
}

void zmq::xpub_t::xattach_pipe (pipe_t *pipe_,
                                bool subscribe_to_all_,
                                bool locally_initiated_)
{
    LIBZMQ_UNUSED (locally_initiated_);

    zmq_assert (pipe_);
    _dist.attach (pipe_);

    //  If subscribe_to_all_ is specified, the caller would like to subscribe
    //  to all data on this pipe, implicitly.
    if (subscribe_to_all_)
        _subscriptions.add (NULL, 0, pipe_);

    // if welcome message exists, send a copy of it
    if (_welcome_msg.size () > 0) {
        msg_t copy;
        copy.init ();
        int rc = copy.copy (_welcome_msg);
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
        metadata_t *metadata = sub.metadata ();
        unsigned char *msg_data = static_cast<unsigned char *> (sub.data ()),
                      *data = NULL;
        size_t size = 0;
        bool subscribe = false;

        //  Apply the subscription to the trie
        if (sub.is_subscribe () || sub.is_cancel ()) {
            data = static_cast<unsigned char *> (sub.command_body ());
            size = sub.command_body_size ();
            subscribe = sub.is_subscribe ();
        } else if (sub.size () > 0) {
            unsigned char first = *msg_data;
            if (first == 0 || first == 1) {
                data = msg_data + 1;
                size = sub.size () - 1;
                subscribe = first == 1;
            }
        } else {
            //  Process user message coming upstream from xsub socket
            _pending_data.push_back (blob_t (msg_data, sub.size ()));
            if (metadata)
                metadata->add_ref ();
            _pending_metadata.push_back (metadata);
            _pending_flags.push_back (sub.flags ());
            sub.close ();
            continue;
        }

        if (_manual) {
            // Store manual subscription to use on termination
            if (!subscribe)
                _manual_subscriptions.rm (data, size, pipe_);
            else
                _manual_subscriptions.add (data, size, pipe_);

            _pending_pipes.push_back (pipe_);

            //  ZMTP 3.1 hack: we need to support sub/cancel commands, but
            //  we can't give them back to userspace as it would be an API
            //  breakage since the payload of the message is completely
            //  different. Manually craft an old-style message instead.
            data = data - 1;
            size = size + 1;
            if (subscribe)
                *data = 1;
            else
                *data = 0;

            _pending_data.push_back (blob_t (data, size));
            if (metadata)
                metadata->add_ref ();
            _pending_metadata.push_back (metadata);
            _pending_flags.push_back (0);
        } else {
            bool notify;
            if (!subscribe) {
                mtrie_t::rm_result rm_result =
                  _subscriptions.rm (data, size, pipe_);
                //  TODO reconsider what to do if rm_result == mtrie_t::not_found
                notify = rm_result != mtrie_t::values_remain || _verbose_unsubs;
            } else {
                bool first_added = _subscriptions.add (data, size, pipe_);
                notify = first_added || _verbose_subs;
            }

            //  If the request was a new subscription, or the subscription
            //  was removed, or verbose mode is enabled, store it so that
            //  it can be passed to the user on next recv call.
            if (options.type == ZMQ_XPUB && notify) {
                data = data - 1;
                size = size + 1;
                if (subscribe)
                    *data = 1;
                else
                    *data = 0;

                _pending_data.push_back (blob_t (data, size));
                if (metadata)
                    metadata->add_ref ();
                _pending_metadata.push_back (metadata);
                _pending_flags.push_back (0);
            }
        }
        sub.close ();
    }
}

void zmq::xpub_t::xwrite_activated (pipe_t *pipe_)
{
    _dist.activated (pipe_);
}

int zmq::xpub_t::xsetsockopt (int option_,
                              const void *optval_,
                              size_t optvallen_)
{
    if (option_ == ZMQ_XPUB_VERBOSE || option_ == ZMQ_XPUB_VERBOSER
        || option_ == ZMQ_XPUB_MANUAL_LAST_VALUE || option_ == ZMQ_XPUB_NODROP
        || option_ == ZMQ_XPUB_MANUAL) {
        if (optvallen_ != sizeof (int)
            || *static_cast<const int *> (optval_) < 0) {
            errno = EINVAL;
            return -1;
        }
        if (option_ == ZMQ_XPUB_VERBOSE) {
            _verbose_subs = (*static_cast<const int *> (optval_) != 0);
            _verbose_unsubs = false;
        } else if (option_ == ZMQ_XPUB_VERBOSER) {
            _verbose_subs = (*static_cast<const int *> (optval_) != 0);
            _verbose_unsubs = _verbose_subs;
        } else if (option_ == ZMQ_XPUB_MANUAL_LAST_VALUE) {
            _manual = (*static_cast<const int *> (optval_) != 0);
            _send_last_pipe = _manual;
        } else if (option_ == ZMQ_XPUB_NODROP)
            _lossy = (*static_cast<const int *> (optval_) == 0);
        else if (option_ == ZMQ_XPUB_MANUAL)
            _manual = (*static_cast<const int *> (optval_) != 0);
    } else if (option_ == ZMQ_SUBSCRIBE && _manual) {
        if (_last_pipe != NULL)
            _subscriptions.add ((unsigned char *) optval_, optvallen_,
                                _last_pipe);
    } else if (option_ == ZMQ_UNSUBSCRIBE && _manual) {
        if (_last_pipe != NULL)
            _subscriptions.rm ((unsigned char *) optval_, optvallen_,
                               _last_pipe);
    } else if (option_ == ZMQ_XPUB_WELCOME_MSG) {
        _welcome_msg.close ();

        if (optvallen_ > 0) {
            int rc = _welcome_msg.init_size (optvallen_);
            errno_assert (rc == 0);

            unsigned char *data =
              static_cast<unsigned char *> (_welcome_msg.data ());
            memcpy (data, optval_, optvallen_);
        } else
            _welcome_msg.init ();
    } else {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

static void stub (zmq::mtrie_t::prefix_t data_, size_t size_, void *arg_)
{
    LIBZMQ_UNUSED (data_);
    LIBZMQ_UNUSED (size_);
    LIBZMQ_UNUSED (arg_);
}

void zmq::xpub_t::xpipe_terminated (pipe_t *pipe_)
{
    if (_manual) {
        //  Remove the pipe from the trie and send corresponding manual
        //  unsubscriptions upstream.
        _manual_subscriptions.rm (pipe_, send_unsubscription, this, false);
        //  Remove pipe without actually sending the message as it was taken
        //  care of by the manual call above. subscriptions is the real mtrie,
        //  so the pipe must be removed from there or it will be left over.
        _subscriptions.rm (pipe_, stub, (void *) NULL, false);
    } else {
        //  Remove the pipe from the trie. If there are topics that nobody
        //  is interested in anymore, send corresponding unsubscriptions
        //  upstream.
        _subscriptions.rm (pipe_, send_unsubscription, this, !_verbose_unsubs);
    }

    _dist.pipe_terminated (pipe_);
}

void zmq::xpub_t::mark_as_matching (pipe_t *pipe_, xpub_t *self_)
{
    self_->_dist.match (pipe_);
}

void zmq::xpub_t::mark_last_pipe_as_matching (pipe_t *pipe_, xpub_t *self_)
{
    if (self_->_last_pipe == pipe_)
        self_->_dist.match (pipe_);
}

int zmq::xpub_t::xsend (msg_t *msg_)
{
    bool msg_more = (msg_->flags () & msg_t::more) != 0;

    //  For the first part of multi-part message, find the matching pipes.
    if (!_more) {
        if (unlikely (_manual && _last_pipe && _send_last_pipe)) {
            _subscriptions.match (static_cast<unsigned char *> (msg_->data ()),
                                  msg_->size (), mark_last_pipe_as_matching,
                                  this);
            _last_pipe = NULL;
        } else
            _subscriptions.match (static_cast<unsigned char *> (msg_->data ()),
                                  msg_->size (), mark_as_matching, this);
        // If inverted matching is used, reverse the selection now
        if (options.invert_matching) {
            _dist.reverse_match ();
        }
    }

    int rc = -1; //  Assume we fail
    if (_lossy || _dist.check_hwm ()) {
        if (_dist.send_to_matching (msg_) == 0) {
            //  If we are at the end of multi-part message we can mark
            //  all the pipes as non-matching.
            if (!msg_more)
                _dist.unmatch ();
            _more = msg_more;
            rc = 0; //  Yay, sent successfully
        }
    } else
        errno = EAGAIN;
    return rc;
}

bool zmq::xpub_t::xhas_out ()
{
    return _dist.has_out ();
}

int zmq::xpub_t::xrecv (msg_t *msg_)
{
    //  If there is at least one
    if (_pending_data.empty ()) {
        errno = EAGAIN;
        return -1;
    }

    // User is reading a message, set last_pipe and remove it from the deque
    if (_manual && !_pending_pipes.empty ()) {
        _last_pipe = _pending_pipes.front ();
        _pending_pipes.pop_front ();
    }

    int rc = msg_->close ();
    errno_assert (rc == 0);
    rc = msg_->init_size (_pending_data.front ().size ());
    errno_assert (rc == 0);
    memcpy (msg_->data (), _pending_data.front ().data (),
            _pending_data.front ().size ());

    // set metadata only if there is some
    if (metadata_t *metadata = _pending_metadata.front ()) {
        msg_->set_metadata (metadata);
        // Remove ref corresponding to vector placement
        metadata->drop_ref ();
    }

    msg_->set_flags (_pending_flags.front ());
    _pending_data.pop_front ();
    _pending_metadata.pop_front ();
    _pending_flags.pop_front ();
    return 0;
}

bool zmq::xpub_t::xhas_in ()
{
    return !_pending_data.empty ();
}

void zmq::xpub_t::send_unsubscription (zmq::mtrie_t::prefix_t data_,
                                       size_t size_,
                                       xpub_t *self_)
{
    if (self_->options.type != ZMQ_PUB) {
        //  Place the unsubscription to the queue of pending (un)subscriptions
        //  to be retrieved by the user later on.
        blob_t unsub (size_ + 1);
        *unsub.data () = 0;
        if (size_ > 0)
            memcpy (unsub.data () + 1, data_, size_);
        self_->_pending_data.ZMQ_PUSH_OR_EMPLACE_BACK (ZMQ_MOVE (unsub));
        self_->_pending_metadata.push_back (NULL);
        self_->_pending_flags.push_back (0);

        if (self_->_manual) {
            self_->_last_pipe = NULL;
            self_->_pending_pipes.push_back (NULL);
        }
    }
}
