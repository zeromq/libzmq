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

#include "zmq_encoder.hpp"
#include "i_inout.hpp"
#include "wire.hpp"

zmq::zmq_encoder_t::zmq_encoder_t () :
    source (NULL)
{
    zmq_msg_init (&in_progress);

    //  Write 0 bytes to the batch and go to message_ready state.
    next_step (NULL, 0, &zmq_encoder_t::message_ready, true);
}

zmq::zmq_encoder_t::~zmq_encoder_t ()
{
    zmq_msg_close (&in_progress);
}

void zmq::zmq_encoder_t::set_inout (i_inout *source_)
{
    source = source_;
}

bool zmq::zmq_encoder_t::size_ready ()
{
    //  Write message body into the buffer.
    next_step (zmq_msg_data (&in_progress), zmq_msg_size (&in_progress),
        &zmq_encoder_t::message_ready, false);
    return true;
}

bool zmq::zmq_encoder_t::message_ready ()
{
    //  Read new message from the dispatcher. If there is none, return false.
    //  Note that new state is set only if write is successful. That way
    //  unsuccessful write will cause retry on the next state machine
    //  invocation.
    if (!source->read (&in_progress))
        return false;

    size_t size = zmq_msg_size (&in_progress);

    //  For messages less than 255 bytes long, write one byte of message size.
    //  For longer messages write 0xff escape character followed by 8-byte
    //  message size.
    if (size < 255) {
        tmpbuf [0] = (unsigned char) size;
        next_step (tmpbuf, 1, &zmq_encoder_t::size_ready, true);
    }
    else {
        tmpbuf [0] = 0xff;
        put_uint64 (tmpbuf + 1, size);
        next_step (tmpbuf, 9, &zmq_encoder_t::size_ready, true);
    }
    return true;
}
