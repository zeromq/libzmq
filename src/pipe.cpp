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

#include <pthread.h>

#include "pipe.hpp"

zmq::reader_t::reader_t (object_t *parent_, pipe_t *pipe_,
      uint64_t hwm_, uint64_t lwm_) :
    object_t (parent_),
    pipe (pipe_),
    peer (&pipe_->writer),
    hwm (hwm_),
    lwm (lwm_),
    index (-1),
    endpoint (NULL)
{
}

zmq::reader_t::~reader_t ()
{
}

bool zmq::reader_t::read (zmq_msg_t *msg_)
{
    return pipe->read (msg_);

    //  TODO: Adjust the size of the pipe.
}

void zmq::reader_t::set_endpoint (i_endpoint *endpoint_)
{
    endpoint = endpoint_;
}

void zmq::reader_t::set_index (int index_)
{
    index = index_;
}

int zmq::reader_t::get_index ()
{
    return index;
}

void zmq::reader_t::process_revive ()
{
    endpoint->revive (this);
}

zmq::writer_t::writer_t (object_t *parent_, pipe_t *pipe_,
      uint64_t hwm_, uint64_t lwm_) :
    object_t (parent_),
    pipe (pipe_),
    peer (&pipe_->reader),
    hwm (hwm_),
    lwm (lwm_)
{
}

zmq::writer_t::~writer_t ()
{
}

bool zmq::writer_t::check_write (uint64_t size_)
{
    //  TODO: Check whether hwm is exceeded.

    return true;
}

bool zmq::writer_t::write (struct zmq_msg_t *msg_)
{
    pipe->write (*msg_);
    return true;

    //  TODO: Adjust size of the pipe.
}

void zmq::writer_t::flush ()
{
    if (!pipe->flush ())
        send_revive (peer);
}

zmq::pipe_t::pipe_t (object_t *reader_parent_, object_t *writer_parent_,
      uint64_t hwm_, uint64_t lwm_) :
    reader (reader_parent_, this, hwm_, lwm_),
    writer (writer_parent_, this, hwm_, lwm_)
{
}

zmq::pipe_t::~pipe_t ()
{
}

