/*
    Copyright (c) 2007-2010 iMatix Corporation

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

#include "../bindings/c/zmq.h"

#include "lb.hpp"
#include "pipe.hpp"
#include "err.hpp"

zmq::lb_t::lb_t () :
    active (0),
    current (0)
{
}

zmq::lb_t::~lb_t ()
{
    for (pipes_t::size_type i = 0; i != pipes.size (); i++)
        pipes [i]->term ();
}

void zmq::lb_t::attach (writer_t *pipe_)
{
    pipes.push_back (pipe_);
    pipes.swap (active, pipes.size () - 1);
    active++;
}

void zmq::lb_t::detach (writer_t *pipe_)
{
    //  Remove the pipe from the list; adjust number of active pipes
    //  accordingly.
    if (pipes.index (pipe_) < active) {
        active--;
        if (current == active)
            current = 0;
    }
    pipes.erase (pipe_);
}

void zmq::lb_t::kill (writer_t *pipe_)
{
    //  Move the pipe to the list of inactive pipes.
    active--;
    if (current == active)
        current = 0;
    pipes.swap (pipes.index (pipe_), active);
}

void zmq::lb_t::revive (writer_t *pipe_)
{
    //  Move the pipe to the list of active pipes.
    pipes.swap (pipes.index (pipe_), active);
    active++;
}

int zmq::lb_t::send (zmq_msg_t *msg_, int flags_)
{
    //  If there are no pipes we cannot send the message.
    if (pipes.empty ()) {
        errno = EAGAIN;
        return -1;
    }

    //  TODO: Implement this once queue limits are in-place.
    zmq_assert (pipes [current]->check_write (zmq_msg_size (msg_)));

    //  Push message to the selected pipe.
    pipes [current]->write (msg_);
    pipes [current]->flush ();

    //  Detach the message from the data buffer.
    int rc = zmq_msg_init (msg_);
    zmq_assert (rc == 0);

    //  Move to the next pipe (load-balancing).
    current++;
    if (current >= active)
        current = 0;

    return 0;
}

bool zmq::lb_t::has_out ()
{
    for (int count = active; count != 0; count--) {

        //  We should be able to write at least 1-byte message to interrupt
        //  polling for POLLOUT.
        //  TODO: Shouldn't we use a saner value here?
        if (pipes [current]->check_write (1))
            return true;
        current++;
        if (current >= active)
            current = 0;
    }

    return false;
}

