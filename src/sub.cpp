/*
    Copyright (c) 2007-2009 FastMQ Inc.

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

#include <string.h>

#include "../bindings/c/zmq.h"

#include "sub.hpp"
#include "err.hpp"

zmq::sub_t::sub_t (class app_thread_t *parent_) :
    socket_base_t (parent_),
    all_count (0)
{
    options.requires_in = true;
    options.requires_out = false;
}

zmq::sub_t::~sub_t ()
{
}

void zmq::sub_t::xattach_pipes (class reader_t *inpipe_,
    class writer_t *outpipe_)
{
    zmq_assert (inpipe_ && !outpipe_);
    fq.attach (inpipe_);
}

void zmq::sub_t::xdetach_inpipe (class reader_t *pipe_)
{
    zmq_assert (pipe_);
    fq.detach (pipe_);
}

void zmq::sub_t::xdetach_outpipe (class writer_t *pipe_)
{
    //  SUB socket is read-only thus there should be no outpipes.
    zmq_assert (false);
}

void zmq::sub_t::xkill (class reader_t *pipe_)
{
    fq.kill (pipe_);
}

void zmq::sub_t::xrevive (class reader_t *pipe_)
{
    fq.revive (pipe_);
}

int zmq::sub_t::xsetsockopt (int option_, const void *optval_,
    size_t optvallen_)
{
    if (option_ == ZMQ_SUBSCRIBE) {
        if (!optvallen_)
            all_count++;
        else 
            subscriptions.insert (std::string ((const char*) optval_,
                optvallen_));
        return 0;
    }
    
    if (option_ == ZMQ_UNSUBSCRIBE) {
        if (!optvallen_) {
            if (!all_count) {
                errno = EINVAL;
                return -1;
            }
            all_count--;
        }
        else {
            subscriptions_t::iterator it = subscriptions.find (
                std::string ((const char*) optval_, optvallen_));
            if (it == subscriptions.end ()) {
                errno = EINVAL;
                return -1;
            }
            subscriptions.erase (it);
        }
        return 0;
    }

    errno = EINVAL;
    return -1;
}

int zmq::sub_t::xsend (zmq_msg_t *msg_, int flags_)
{
    errno = ENOTSUP;
    return -1;
}

int zmq::sub_t::xflush ()
{
    errno = ENOTSUP;
    return -1;
}

int zmq::sub_t::xrecv (zmq_msg_t *msg_, int flags_)
{
    //  Get a message using fair queueing algorithm.
    int rc = fq.recv (msg_, flags_);

    //  If there's no message available, return immediately.
    if (rc != 0 && errno == EAGAIN)
        return -1;

    //  If there is at least one * subscription, the message matches.
    if (all_count)
        return 0;

    //  Check whether the message matches at least one prefix subscription.
    //  TODO: Make this efficient - O(log(n)) where n is number of characters in
    //  the longest subscription string.
    for (subscriptions_t::iterator it = subscriptions.begin ();
          it != subscriptions.end (); it++) {
        size_t msg_size = zmq_msg_size (msg_);
        size_t sub_size = it->size ();
        if (sub_size <= msg_size &&
              memcmp (zmq_msg_data (msg_), it->data (), sub_size) == 0)
            return 0;
    }

    //  The message did not pass the filter. Trim it.
    //  Note that we are returning a different error code so that the caller
    //  knows there are more messages available. We cannot loop here as
    //  a stream of non-matching messages would create a DoS situation.
    zmq_msg_close (msg_);
    zmq_msg_init (msg_);
    errno = EINPROGRESS;
    return -1;
}

bool zmq::sub_t::xhas_in ()
{
    //  TODO:  This is more complex as we have to ignore all the messages that
    //         don't fit the filter.
    zmq_assert (false);
    return false;
}

bool zmq::sub_t::xhas_out ()
{
    return false;
}
