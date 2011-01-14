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

#include "../include/zmq.h"

#include "dist.hpp"
#include "pipe.hpp"
#include "err.hpp"
#include "own.hpp"
#include "msg_content.hpp"

zmq::dist_t::dist_t (own_t *sink_) :
    active (0),
    more (false),
    sink (sink_),
    terminating (false)
{
}

zmq::dist_t::~dist_t ()
{
    zmq_assert (pipes.empty ());
}

void zmq::dist_t::attach (writer_t *pipe_)
{
    pipe_->set_event_sink (this);

    pipes.push_back (pipe_);
    pipes.swap (active, pipes.size () - 1);
    active++;

    if (terminating) {
        sink->register_term_acks (1);
        pipe_->terminate ();
    }
}

void zmq::dist_t::terminate ()
{
    zmq_assert (!terminating);
    terminating = true;

    sink->register_term_acks (pipes.size ());
    for (pipes_t::size_type i = 0; i != pipes.size (); i++)
        pipes [i]->terminate ();
}

void zmq::dist_t::terminated (writer_t *pipe_)
{
    //  Remove the pipe from the list; adjust number of active pipes
    //  accordingly.
    if (pipes.index (pipe_) < active)
        active--;
    pipes.erase (pipe_);

    if (terminating)
        sink->unregister_term_ack ();
}

void zmq::dist_t::activated (writer_t *pipe_)
{
    //  Move the pipe to the list of active pipes.
    pipes.swap (pipes.index (pipe_), active);
    active++;
}

int zmq::dist_t::send (zmq_msg_t *msg_, int flags_)
{
    //  If there are no active pipes available, simply drop the message.
    if (active == 0) {
        int rc = zmq_msg_close (msg_);
        zmq_assert (rc == 0);
        rc = zmq_msg_init (msg_);
        zmq_assert (rc == 0);
        return 0;
    }

    msg_content_t *content = (msg_content_t*) msg_->content;

    //  For VSMs the copying is straighforward.
    if (content == (msg_content_t*) ZMQ_VSM) {
        for (pipes_t::size_type i = 0; i < active;)
            if (write (pipes [i], msg_))
                i++;
        int rc = zmq_msg_init (msg_);
        zmq_assert (rc == 0);
        return 0;
    }

    //  Optimisation for the case when there's only a single pipe
    //  to send the message to - no refcount adjustment i.e. no atomic
    //  operations are needed.
    if (active == 1) {
        if (!write (pipes [0], msg_)) {
            int rc = zmq_msg_close (msg_);
            zmq_assert (rc == 0);
        }
        int rc = zmq_msg_init (msg_);
        zmq_assert (rc == 0);
        return 0;
    }

    //  There are at least 2 destinations for the message. That means we have
    //  to deal with reference counting. First add N-1 references to
    //  the content (we are holding one reference anyway, that's why -1).
    if (msg_->flags & ZMQ_MSG_SHARED)
        content->refcnt.add (active - 1);
    else {
        content->refcnt.set (active);
        msg_->flags |= ZMQ_MSG_SHARED;
    }

    //  Push the message to all destinations.
    for (pipes_t::size_type i = 0; i < active;) {
        if (!write (pipes [i], msg_))
            content->refcnt.sub (1);
        else
            i++;
    }

    //  Detach the original message from the data buffer.
    int rc = zmq_msg_init (msg_);
    zmq_assert (rc == 0);

    return 0;
}

bool zmq::dist_t::has_out ()
{
    return true;
}

bool zmq::dist_t::write (class writer_t *pipe_, zmq_msg_t *msg_)
{
    if (!pipe_->write (msg_)) {
        active--;
        pipes.swap (pipes.index (pipe_), active);
        return false;
    }
    if (!(msg_->flags & ZMQ_MSG_MORE))
        pipe_->flush ();
    return true;
}

