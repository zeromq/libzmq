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

#include "fq.hpp"
#include "pipe.hpp"
#include "err.hpp"

zmq::fq_t::fq_t () :
    active (0),
    current (0)
{
}

zmq::fq_t::~fq_t ()
{
    for (pipes_t::size_type i = 0; i != pipes.size (); i++)
        pipes [i]->term ();
}

void zmq::fq_t::attach (reader_t *pipe_)
{
    pipes.push_back (pipe_);
    pipes.swap (active, pipes.size () - 1);
    active++;
}

void zmq::fq_t::detach (reader_t *pipe_)
{
    //  Remove the pipe from the list; adjust number of active pipes
    //  accordingly.
    if (pipes.index (pipe_) < active)
        active--;
    pipes.erase (pipe_);
}

void zmq::fq_t::kill (reader_t *pipe_)
{
    //  Move the pipe to the list of inactive pipes.
    active--;
    pipes.swap (pipes.index (pipe_), active);
}

void zmq::fq_t::revive (reader_t *pipe_)
{
    //  Move the pipe to the list of active pipes.
    pipes.swap (pipes.index (pipe_), active);
    active++;
}

int zmq::fq_t::recv (zmq_msg_t *msg_, int flags_)
{
    //  Deallocate old content of the message.
    zmq_msg_close (msg_);

    //  Round-robin over the pipes to get next message.
    for (int count = active; count != 0; count--) {
        bool fetched = pipes [current]->read (msg_);
        current++;
        if (current >= active)
            current = 0;
        if (fetched)
            return 0;
    }

    //  No message is available. Initialise the output parameter
    //  to be a 0-byte message.
    zmq_msg_init (msg_);
    errno = EAGAIN;
    return -1;
}

bool zmq::fq_t::has_in ()
{
    //  Note that messing with current doesn't break the fairness of fair
    //  queueing algorithm. If there are no messages available current will
    //  get back to its original value. Otherwise it'll point to the first
    //  pipe holding messages, skipping only pipes with no messages available.
    for (int count = active; count != 0; count--) {
        if (pipes [current]->check_read ())
            return true;
        current++;
        if (current >= active)
            current = 0;
    }

    return false;
}

