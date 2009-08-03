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

#include "../include/zmq.h"

#include "fair_aggregator.hpp"
#include "err.hpp"
#include "pipe_reader.hpp"
#include "session.hpp"

//  Swaps pipes at specified indices. 
#define swap_pipes(i1_, i2_) \
    std::swap (pipes [i1_], pipes [i2_]);\
    pipes [i1_]->set_index (i1_);\
    pipes [i2_]->set_index (i2_);

zmq::fair_aggregator_t::fair_aggregator_t () :
    session (NULL),
    active (0),
    current (0)
{
}

void zmq::fair_aggregator_t::set_session (session_t *session_)
{
    zmq_assert (!session);
    session = session_;
}

void zmq::fair_aggregator_t::shutdown ()
{
    //  No need to deallocate pipes here. They'll be deallocated during the
    //  shutdown of the dispatcher.
    delete this;
}

void zmq::fair_aggregator_t::terminate ()
{
    //  Pipe unregisters itself during the call to terminate, so the pipes
    //  list shinks by one in each iteration.
    while (!pipes.empty ())
        pipes [0]->terminate ();

   delete this;
}

zmq::fair_aggregator_t::~fair_aggregator_t ()
{
}

void zmq::fair_aggregator_t::attach_pipe (pipe_reader_t *pipe_)
{
    //  Associate new pipe with the mux object.
    pipe_->set_mux (this);
    pipes.push_back (pipe_);
    active++;
    if (pipes.size () > active)
        swap_pipes (pipes.size () - 1, active - 1);
    if (active == 1)
        session->revive ();
}

void zmq::fair_aggregator_t::detach_pipe (pipe_reader_t *pipe_)
{
    //  Move the pipe from the list of active pipes to the list of idle pipes.
    deactivate (pipe_);
            
    //  Move the pipe to the end of the idle list and remove it.
    swap_pipes (pipe_->get_index (), pipes.size () - 1);
    pipes.pop_back ();
}

bool zmq::fair_aggregator_t::empty ()
{
    return pipes.empty ();
}

bool zmq::fair_aggregator_t::recv (zmq_msg *msg_)
{
    //  Deallocate old content of the message.
    zmq_msg_close (msg_);

    //  O(1) fair queueing. Round-robin over the active pipes to get
    //  next message.
    for (pipes_t::size_type i = active; i != 0; i--) {

        //  Update current.
        current = (current + 1) % active;
        
        //  Try to read from current.
        if (pipes [current]->read (msg_))
            return true;
    }

    //  No message is available. Initialise the output parameter
    //  to be a 0-byte message.
    zmq_msg_init (msg_);
    return false;
}

void zmq::fair_aggregator_t::deactivate (pipe_reader_t *pipe_)
{
    int index = pipe_->get_index ();

    //  Suspend an active pipe.
    swap_pipes (index, active - 1);
    active--;

    //  If the deactiveted pipe is the current one, shift the current one pipe
    //  backwards so that the pipe that replaced the deactiveted one will be
    //  processed immediately rather than skipped.
    if (index == (int) current) {
        index--;
        if (index == -1)
            index = active - 1;
        current = index;
    }
}

void zmq::fair_aggregator_t::reactivate (pipe_reader_t *pipe_)
{
    //  Revive an idle pipe.
    swap_pipes (pipe_->get_index (), active);
    active++;
    if (active == 1)
        session->revive ();
}
