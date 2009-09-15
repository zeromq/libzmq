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

#include "../c/zmq.h"

#include "pub.hpp"
#include "err.hpp"

zmq::pub_t::pub_t (class app_thread_t *parent_) :
    socket_base_t (parent_, ZMQ_SUB)
{
}

zmq::pub_t::~pub_t ()
{
}

int zmq::pub_t::recv (struct zmq_msg_t *msg_, int flags_)
{
    errno = EFAULT;
    return -1;
}

