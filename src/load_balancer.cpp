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

#include "load_balancer.hpp"
#include "pipe_writer.hpp"
#include "err.hpp"
#include "session.hpp"
#include "msg.hpp"

zmq::load_balancer_t::load_balancer_t () :
    session (NULL),
    current (0)
{
}

void zmq::load_balancer_t::set_session (session_t *session_)
{
    zmq_assert (!session);
    session = session_;
}

void zmq::load_balancer_t::shutdown ()
{
    //  No need to deallocate pipes here. They'll be deallocated during the
    //  shutdown of the dispatcher.
    delete this;
}

void zmq::load_balancer_t::terminate ()
{
    //  Pipe unregisters itself during the call to terminate, so the pipes
    //  list shinks by one in each iteration.
    while (!pipes.empty ())
        pipes [0]->terminate ();

   delete this;
}

zmq::load_balancer_t::~load_balancer_t ()
{
}

void zmq::load_balancer_t::attach_pipe (pipe_writer_t *pipe_)
{
    //  Associate demux with a new pipe.
    pipe_->set_demux (this);
    pipe_->set_index (pipes.size ());
    pipes.push_back (pipe_);
}

void zmq::load_balancer_t::detach_pipe (pipe_writer_t *pipe_)
{
    //  Release the reference to the pipe.
    int index = pipe_->get_index ();
    pipe_->set_index (-1);
    pipes [index] = pipes.back ();
    pipes [index]->set_index (index);
    pipes.pop_back ();
}

bool zmq::load_balancer_t::empty ()
{
    return pipes.empty ();
}

bool zmq::load_balancer_t::send (zmq_msg *msg_)
{
    //  If there are no pipes, message cannot be sent.
    if (pipes.size () == 0)
        return false;

    //  Find the first pipe that is ready to accept the message.
    bool found = false;
    for (pipes_t::size_type i = 0; !found && i < pipes.size (); i++) {
//        if (pipes [current]->check_write (msg))
            found = true;
//        else
//            current = (current + 1) % pipes.size ();
    }

    //  Oops, no pipe is ready to accept the message.
    if (!found)
        return false;

    //  Send the message to the selected pipe.
    write_to_pipe (pipes [current], msg_);
    current = (current + 1) % pipes.size ();

    //  Detach the original message from the data buffer.
    zmq_msg_init (msg_);

    return true;
}

void zmq::load_balancer_t::flush ()
{
    //  Flush all pipes. If there's large number of pipes, it can be pretty
    //  inefficient (especially if there's new message only in a single pipe).
    //  Can it be improved?
    for (pipes_t::iterator it = pipes.begin (); it != pipes.end (); it ++)
        (*it)->flush ();
}

void zmq::load_balancer_t::write_to_pipe (class pipe_writer_t *pipe_,
    struct zmq_msg *msg_)
{
    if (!pipe_->write (msg_)) {
        //  TODO: Push gap notification to the pipe.
        zmq_assert (false);
    }
}

