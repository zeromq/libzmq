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

#include "zmq_listener.hpp"
#include "err.hpp"

zmq::zmq_listener_t::zmq_listener_t (object_t *parent_, object_t *owner_) :
    io_object_t (parent_, owner_)
{
}

zmq::zmq_listener_t::~zmq_listener_t ()
{
}

void zmq::zmq_listener_t::process_plug ()
{
    //  TODO:  Register with the I/O thread here.
}
