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

zmq::owned_t::owned_t (object_t *parent_, object_t *owner_) :
    object_t (parent_),
    owner (owner_),
    plugged_in (false),
    terminated (false)
{
}

zmq::owned_t::~owned_t ()
{
}

void zmq::owned_t::process_plug ()
{
    zmq_assert (!plugged_in);

    //  If termination of the object was already requested, destroy it and
    //  send the termination acknowledgement.
    if (terminated) {
        send_term_ack (owner);
        delete this;
        return;
    }

    //  Notify the generic termination mechanism (io_object_t) that the object
    //  is already plugged in.
    plugged_in = true;
}

void zmq::owned_t::term ()
{
    send_term_req (owner, this);
}

void zmq::owned_t::process_term ()
{
    zmq_assert (!terminated);

    //  If termination request has occured even before the object was plugged in
    //  wait till plugging in happens, then acknowledge the termination.
    if (!plugged_in) {
        terminated = true;
        return;
    }

    //  Otherwise, destroy the object and acknowledge the termination
    //  straight away.
    send_term_ack (owner);
    process_unplug ();
    delete this;
}

