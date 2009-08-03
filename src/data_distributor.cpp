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

#include "data_distributor.hpp"
#include "pipe_writer.hpp"
#include "err.hpp"
#include "session.hpp"
#include "msg.hpp"

zmq::data_distributor_t::data_distributor_t () :
    session (NULL)
{
}

void zmq::data_distributor_t::set_session (session_t *session_)
{
    zmq_assert (!session);
    session = session_;
}

void zmq::data_distributor_t::shutdown ()
{
    //  No need to deallocate pipes here. They'll be deallocated during the
    //  shutdown of the dispatcher.
    delete this;
}

void zmq::data_distributor_t::terminate ()
{
    //  Pipe unregisters itself during the call to terminate, so the pipes
    //  list shinks by one in each iteration.
    while (!pipes.empty ())
        pipes [0]->terminate ();

   delete this;
}

zmq::data_distributor_t::~data_distributor_t ()
{
}

void zmq::data_distributor_t::attach_pipe (pipe_writer_t *pipe_)
{
    //  Associate demux with a new pipe.
    pipe_->set_demux (this);
    pipe_->set_index (pipes.size ());
    pipes.push_back (pipe_);
}

void zmq::data_distributor_t::detach_pipe (pipe_writer_t *pipe_)
{
    //  Release the reference to the pipe.
    int index = pipe_->get_index ();
    pipe_->set_index (-1);
    pipes [index] = pipes.back ();
    pipes [index]->set_index (index);
    pipes.pop_back ();
}

bool zmq::data_distributor_t::empty ()
{
    return pipes.empty ();
}

bool zmq::data_distributor_t::send (zmq_msg *msg_)
{
    int pipes_count = pipes.size ();

    //  If there are no pipes available, simply drop the message.
    if (pipes_count == 0) {
        zmq_msg_close (msg_);
        zmq_msg_init (msg_);
        return true;
    }

    //  TODO: ???
    //  First check whether all pipes are available for writing.
//    for (pipes_t::iterator it = pipes.begin (); it != pipes.end (); it ++)
//        if (!(*it)->check_write (msg_))
//            return false;

    //  For VSMs the copying is straighforward.
    if (msg_->content == (zmq_msg_content*) ZMQ_VSM) {
        for (pipes_t::iterator it = pipes.begin (); it != pipes.end (); it ++)
            write_to_pipe (*it, msg_);
        zmq_msg_init (msg_);
        return true;
    }

    //  Optimisation for the case when there's only a single pipe
    //  to send the message to - no refcount adjustment (i.e. atomic
    //  operations) needed.
    if (pipes_count == 1) {
        write_to_pipe (*pipes.begin (), msg_);
        zmq_msg_init (msg_);
        return true;
    }

    //  There are at least 2 destinations for the message. That means we have
    //  to deal with reference counting. First add N-1 references to
    //  the content (we are holding one reference anyway, that's why the -1).
    if (msg_->shared)
        msg_->content->refcnt.add (pipes_count - 1);
    else {
        msg_->shared = true;
        // TODO: Add memory barrier here.
        msg_->content->refcnt.set (pipes_count);
    }

    //  Push the message to all destinations.
    for (pipes_t::iterator it = pipes.begin (); it != pipes.end (); it ++)
        write_to_pipe (*it, msg_);

    //  Detach the original message from the data buffer.
    zmq_msg_init (msg_);

    return true;
}

void zmq::data_distributor_t::flush ()
{
    //  Flush all pipes. If there's large number of pipes, it can be pretty
    //  inefficient (especially if there's new message only in a single pipe).
    //  Can it be improved?
    for (pipes_t::iterator it = pipes.begin (); it != pipes.end (); it ++)
        (*it)->flush ();
}

void zmq::data_distributor_t::write_to_pipe (class pipe_writer_t *pipe_,
    struct zmq_msg *msg_)
{
    if (!pipe_->write (msg_)) {
        //  TODO: Push gap notification to the pipe.
        zmq_assert (false);
    }
}

