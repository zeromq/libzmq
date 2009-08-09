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

#include "io_object.hpp"
#include "io_thread.hpp"

zmq::io_object_t::io_object_t (io_thread_t *parent_, object_t *owner_) :
    object_t (parent_),
    owner (owner_)
{
    //  Retrieve the poller from the thread we are running in.
    poller = parent_->get_poller ();
}

zmq::io_object_t::~io_object_t ()
{
}

zmq::handle_t zmq::io_object_t::add_fd (fd_t fd_, i_poll_events *events_)
{
    return poller->add_fd (fd_, events_);
}

void zmq::io_object_t::rm_fd (handle_t handle_)
{
    poller->rm_fd (handle_);
}

void zmq::io_object_t::set_pollin (handle_t handle_)
{
    poller->set_pollin (handle_);
}

void zmq::io_object_t::reset_pollin (handle_t handle_)
{
    poller->reset_pollin (handle_);
}

void zmq::io_object_t::set_pollout (handle_t handle_)
{
    poller->set_pollout (handle_);
}

void zmq::io_object_t::reset_pollout (handle_t handle_)
{
    poller->reset_pollout (handle_);
}

void zmq::io_object_t::add_timer (i_poll_events *events_)
{
    poller->add_timer (events_);
}

void zmq::io_object_t::cancel_timer (i_poll_events *events_)
{
    poller->cancel_timer (events_);
}

void zmq::io_object_t::term ()
{
    send_term_req (owner, this);
}

void zmq::io_object_t::process_term ()
{
    send_term_ack (owner);
    delete this;
}
