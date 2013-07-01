/*
    Copyright (c) 2007-2013 Contributors as noted in the AUTHORS file

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
#include "msg.hpp"
#include "likely.hpp"

zmq::dist_t::dist_t () :
    matching (0),
    active (0),
    eligible (0),
    more (false)
{
}

zmq::dist_t::~dist_t ()
{
    zmq_assert (pipes.empty ());
}

void zmq::dist_t::attach (pipe_t *pipe_)
{
    //  If we are in the middle of sending a message, we'll add new pipe
    //  into the list of eligible pipes. Otherwise we add it to the list
    //  of active pipes.
    if (more) {
        pipes.push_back (pipe_);
        pipes.swap (eligible, pipes.size () - 1);
        eligible++;
    }
    else {
        pipes.push_back (pipe_);
        pipes.swap (active, pipes.size () - 1);
        active++;
        eligible++;
    }
}

void zmq::dist_t::match (pipe_t *pipe_)
{
    //  If pipe is already matching do nothing.
    if (pipes.index (pipe_) < matching)
        return;

    //  If the pipe isn't eligible, ignore it.
    if (pipes.index (pipe_) >= eligible)
        return;

    //  Mark the pipe as matching.
    pipes.swap (pipes.index (pipe_), matching);
    matching++;    
}

void zmq::dist_t::unmatch ()
{
    matching = 0;
}

void zmq::dist_t::pipe_terminated (pipe_t *pipe_)
{
    //  Remove the pipe from the list; adjust number of matching, active and/or
    //  eligible pipes accordingly.
    if (pipes.index (pipe_) < matching) {
        pipes.swap (pipes.index (pipe_), matching - 1);
        matching--;
    }
    if (pipes.index (pipe_) < active) {
        pipes.swap (pipes.index (pipe_), active - 1);
        active--;
    }
    if (pipes.index (pipe_) < eligible) {
        pipes.swap (pipes.index (pipe_), eligible - 1);
        eligible--;
    }

    pipes.erase (pipe_);
}

void zmq::dist_t::activated (pipe_t *pipe_)
{
    //  Move the pipe from passive to eligible state.
    pipes.swap (pipes.index (pipe_), eligible);
    eligible++;

    //  If there's no message being sent at the moment, move it to
    //  the active state.
    if (!more) {
        pipes.swap (eligible - 1, active);
        active++;
    }
}

int zmq::dist_t::send_to_all (msg_t *msg_)
{
    matching = active;
    return send_to_matching (msg_);
}

int zmq::dist_t::send_to_matching (msg_t *msg_)
{
    //  Is this end of a multipart message?
    bool msg_more = msg_->flags () & msg_t::more ? true : false;

    //  Push the message to matching pipes.
    distribute (msg_);

    //  If mutlipart message is fully sent, activate all the eligible pipes.
    if (!msg_more)
        active = eligible;

    more = msg_more;

    return 0;
}

void zmq::dist_t::distribute (msg_t *msg_)
{
    //  If there are no matching pipes available, simply drop the message.
    if (matching == 0) {
        int rc = msg_->close ();
        errno_assert (rc == 0);
        rc = msg_->init ();
        errno_assert (rc == 0);
        return;
    }

    if (msg_->is_vsm ()) {
        for (pipes_t::size_type i = 0; i < matching; ++i)
            if(!write (pipes [i], msg_))
                --i; //  Retry last write because index will have been swapped
        int rc = msg_->close();
        errno_assert (rc == 0);
        rc = msg_->init ();
        errno_assert (rc == 0);
        return;
    }

    //  Add matching-1 references to the message. We already hold one reference,
    //  that's why -1.
    msg_->add_refs ((int) matching - 1);

    //  Push copy of the message to each matching pipe.
    int failed = 0;
    for (pipes_t::size_type i = 0; i < matching; ++i)
        if (!write (pipes [i], msg_)) {
            ++failed;
            --i; //  Retry last write because index will have been swapped
        }
    if (unlikely (failed))
        msg_->rm_refs (failed);

    //  Detach the original message from the data buffer. Note that we don't
    //  close the message. That's because we've already used all the references.
    int rc = msg_->init ();
    errno_assert (rc == 0);
}

bool zmq::dist_t::has_out ()
{
    return true;
}

bool zmq::dist_t::write (pipe_t *pipe_, msg_t *msg_)
{
    if (!pipe_->write (msg_)) {
        pipes.swap (pipes.index (pipe_), matching - 1);
        matching--;
        pipes.swap (pipes.index (pipe_), active - 1);
        active--;
        pipes.swap (active, eligible - 1);
        eligible--;
        return false;
    }
    if (!(msg_->flags () & msg_t::more))
        pipe_->flush ();
    return true;
}

