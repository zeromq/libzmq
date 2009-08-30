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

#include "owned.hpp"
#include "err.hpp"

zmq::owned_t::owned_t (object_t *parent_, socket_base_t *owner_) :
    object_t (parent_),
    owner (owner_),
    sent_seqnum (0),
    processed_seqnum (0),
    shutting_down (false)
{
}

zmq::owned_t::~owned_t ()
{
}

void zmq::owned_t::inc_seqnum ()
{
    //  NB: This function may be called from a different thread!
    sent_seqnum.add (1);
}

void zmq::owned_t::process_plug ()
{
    //  Keep track of how many commands were processed so far.
    processed_seqnum++;

    finalise_command ();
}

void zmq::owned_t::process_attach (struct i_engine *engine_)
{
    //  Keep track of how many commands were processed so far.
    processed_seqnum++;

    finalise_command ();
}

void zmq::owned_t::term ()
{
    send_term_req (owner, this);
}

void zmq::owned_t::process_term ()
{
    zmq_assert (!shutting_down);
    shutting_down = true;

    finalise_command ();
}

void zmq::owned_t::finalise_command ()
{
    //  If termination request was already received and there are no more
    //  commands to wait for, terminate the object.
    if (shutting_down && processed_seqnum == sent_seqnum.get ()) {
        process_unplug ();
        send_term_ack (owner);
        delete this;
    }
}

