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

#include "io_object.hpp"
#include "io_thread.hpp"
#include "err.hpp"

zmq::io_object_t::io_object_t (io_thread_t *io_thread_)
{
    //  Retrieve the poller from the thread we are running in.
    poller = io_thread_->get_poller ();
}

zmq::io_object_t::~io_object_t ()
{
}

void zmq::io_object_t::set_io_thread (io_thread_t *io_thread_)
{
    poller = io_thread_->get_poller ();
}

zmq::io_object_t::handle_t zmq::io_object_t::add_fd (fd_t fd_)
{
    return poller->add_fd (fd_, this);
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

void zmq::io_object_t::add_timer ()
{
    poller->add_timer (this);
}

void zmq::io_object_t::cancel_timer ()
{
    poller->cancel_timer (this);
}

void zmq::io_object_t::in_event ()
{
    zmq_assert (false);
}

void zmq::io_object_t::out_event ()
{
    zmq_assert (false);
}

void zmq::io_object_t::timer_event ()
{
    zmq_assert (false);
}
