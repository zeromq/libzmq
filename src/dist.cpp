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

#include "dist.hpp"
#include "pipe.hpp"
#include "err.hpp"
#include "own.hpp"
#include "msg.hpp"

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
    //  If we are in the middle of sending a message, let's postpone plugging
    //  in the pipe.
    if (!terminating && more) {
        new_pipes.push_back (pipe_);
        return;
    }

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

int zmq::dist_t::send (msg_t *msg_, int flags_)
{
    //  Is this end of a multipart message?
    bool msg_more = msg_->flags () & msg_t::more;

    //  Push the message to active pipes.
    distribute (msg_, flags_);

    //  If mutlipart message is fully sent, activate new pipes.
    if (more && !msg_more)
        clear_new_pipes ();

    more = msg_more;

    return 0;
}

void zmq::dist_t::distribute (msg_t *msg_, int flags_)
{
    //  If there are no active pipes available, simply drop the message.
    if (active == 0) {
        int rc = msg_->close ();
        errno_assert (rc == 0);
        rc = msg_->init ();
        zmq_assert (rc == 0);
        return;
    }

    //  Add active-1 references to the message. We already hold one reference,
    //  that's why -1.
    msg_->add_refs (active - 1);

    //  Push copy of the message to each active pipe.
    for (pipes_t::size_type i = 0; i < active;) {
        if (!write (pipes [i], msg_))
            msg_->rm_refs (1);
        else
            i++;
    }

    //  Detach the original message from the data buffer. Note that we don't
    //  close the message. That's because we've already used all the references.
    int rc = msg_->init ();
    errno_assert (rc == 0);
}

bool zmq::dist_t::has_out ()
{
    return true;
}

bool zmq::dist_t::write (class writer_t *pipe_, msg_t *msg_)
{
    if (!pipe_->write (msg_)) {
        active--;
        pipes.swap (pipes.index (pipe_), active);
        return false;
    }
    if (!(msg_->flags () & msg_t::more))
        pipe_->flush ();
    return true;
}

void zmq::dist_t::clear_new_pipes ()
{
    for (new_pipes_t::iterator it = new_pipes.begin (); it != new_pipes.end ();
          ++it) {
        (*it)->set_event_sink (this);
        pipes.push_back (*it);
        pipes.swap (active, pipes.size () - 1);
        active++;
    }
    new_pipes.clear ();
}

