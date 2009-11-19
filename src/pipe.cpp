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

#include "../bindings/c/zmq.h"

#include "pipe.hpp"

zmq::reader_t::reader_t (object_t *parent_, pipe_t *pipe_,
      uint64_t hwm_, uint64_t lwm_) :
    object_t (parent_),
    pipe (pipe_),
    peer (&pipe_->writer),
    hwm (hwm_),
    lwm (lwm_),
    endpoint (NULL)
{
}

zmq::reader_t::~reader_t ()
{
}

bool zmq::reader_t::check_read ()
{
    //  Check if there's an item in the pipe.
    if (pipe->check_read ())
        return true;

    //  If not, deactivate the pipe.
    endpoint->kill (this);
    return false;
}

bool zmq::reader_t::read (zmq_msg_t *msg_)
{
    if (!pipe->read (msg_)) {
        endpoint->kill (this);
        return false;
    }

    //  If delimiter was read, start termination process of the pipe.
    unsigned char *offset = 0;
    if (msg_->content == (void*) (offset + ZMQ_DELIMITER)) {
        if (endpoint)
            endpoint->detach_inpipe (this);
        term ();
        return false;
    }

    //  TODO: Adjust the size of the pipe.

    return true;
}

void zmq::reader_t::set_endpoint (i_endpoint *endpoint_)
{
    endpoint = endpoint_;
}

void zmq::reader_t::term ()
{
    endpoint = NULL;
    send_pipe_term (peer);
}

void zmq::reader_t::process_revive ()
{
    //  Beacuse of command throttling mechanism, incoming termination request
    //  may not have been processed before subsequent send.
    //  In that case endpoint is NULL.
    if (endpoint)
        endpoint->revive (this);
}

void zmq::reader_t::process_pipe_term_ack ()
{
    peer = NULL;
    delete pipe;
}

zmq::writer_t::writer_t (object_t *parent_, pipe_t *pipe_,
      uint64_t hwm_, uint64_t lwm_) :
    object_t (parent_),
    pipe (pipe_),
    peer (&pipe_->reader),
    hwm (hwm_),
    lwm (lwm_),
    endpoint (NULL)
{
}

void zmq::writer_t::set_endpoint (i_endpoint *endpoint_)
{
    endpoint = endpoint_;
}

zmq::writer_t::~writer_t ()
{
}

bool zmq::writer_t::check_write (uint64_t size_)
{
    //  TODO: Check whether hwm is exceeded.

    return true;
}

bool zmq::writer_t::write (zmq_msg_t *msg_)
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

void zmq::writer_t::term ()
{
    endpoint = NULL;

    //  Push delimiter into the pipe.
    //  Trick the compiler to belive that the tag is a valid pointer.
    zmq_msg_t msg;
    const unsigned char *offset = 0;
    msg.content = (void*) (offset + ZMQ_DELIMITER);
    msg.shared = false;
    pipe->write (msg);
    pipe->flush ();
}

void zmq::writer_t::process_pipe_term ()
{
    if (endpoint)
        endpoint->detach_outpipe (this);

    reader_t *p = peer;
    peer = NULL;
    send_pipe_term_ack (p);
}

zmq::pipe_t::pipe_t (object_t *reader_parent_, object_t *writer_parent_,
      uint64_t hwm_, uint64_t lwm_) :
    reader (reader_parent_, this, hwm_, lwm_),
    writer (writer_parent_, this, hwm_, lwm_)
{
    reader.register_pipe (this);
}

zmq::pipe_t::~pipe_t ()
{
    //  Deallocate all the unread messages in the pipe. We have to do it by
    //  hand because zmq_msg_t is a POD, not a class, so there's no associated
    //  destructor.
    zmq_msg_t msg;
    while (read (&msg))
       zmq_msg_close (&msg);

    reader.unregister_pipe (this);
}
