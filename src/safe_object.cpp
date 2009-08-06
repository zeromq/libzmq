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

#include "safe_object.hpp"

zmq::safe_object_t::safe_object_t (class context_t *context_,
        int thread_slot_) :
    object_t (context_, thread_slot_),
    processed_seqnum (0),
    terminating (false)
{
}

zmq::safe_object_t::safe_object_t (object_t *parent_) :
    object_t (parent_),
    processed_seqnum (0),
    terminating (false)
{
}

void zmq::safe_object_t::inc_seqnum ()
{
    //  This function is called from the sender thread to ensure that this
    //  object will still exist when the command sent to it arrives in the
    //  destination thread.
    sent_seqnum.add (1);
}

void zmq::safe_object_t::process_command (struct command_t &cmd_)
{
    object_t::process_command (cmd_);

    //  Adjust sequence number of the last processed command.
    processed_seqnum++;

    //  If we are already in the termination phase and all commands sent to
    //  this object are processed, it's safe to deallocate it.
    if (terminating && sent_seqnum.get () == processed_seqnum)
        delete this;
}

void zmq::safe_object_t::terminate ()
{
    //  Wait till all commands sent to this session are processed.
    terminating = true;

    //  If there's no pending command we can deallocate the session
    //  straight saway.
    if (sent_seqnum.get () == processed_seqnum)
        delete this;
}

bool zmq::safe_object_t::is_terminating ()
{
    return terminating;
}

zmq::safe_object_t::~safe_object_t ()
{
}
