/*
    Copyright (c) 2007-2014 Contributors as noted in the AUTHORS file

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "v2_protocol.hpp"
#include "v2_encoder.hpp"
#include "likely.hpp"
#include "wire.hpp"

zmq::v2_encoder_t::v2_encoder_t (size_t bufsize_) :
    encoder_base_t <v2_encoder_t> (bufsize_)
{
    //  Write 0 bytes to the batch and go to message_ready state.
    next_step (NULL, 0, &v2_encoder_t::message_ready, true);
}

zmq::v2_encoder_t::~v2_encoder_t ()
{
}

void zmq::v2_encoder_t::message_ready ()
{
    //  Encode flags.
    unsigned char &protocol_flags = tmpbuf [0];
    protocol_flags = 0;
    if (in_progress->flags () & msg_t::more)
        protocol_flags |= v2_protocol_t::more_flag;
    if (in_progress->size () > 255)
        protocol_flags |= v2_protocol_t::large_flag;
    if (in_progress->flags () & msg_t::command)
        protocol_flags |= v2_protocol_t::command_flag;

    //  Encode the message length. For messages less then 256 bytes,
    //  the length is encoded as 8-bit unsigned integer. For larger
    //  messages, 64-bit unsigned integer in network byte order is used.
    const size_t size = in_progress->size ();
    if (unlikely (size > 255)) {
        put_uint64 (tmpbuf + 1, size);
        next_step (tmpbuf, 9, &v2_encoder_t::size_ready, false);
    }
    else {
        tmpbuf [1] = static_cast <uint8_t> (size);
        next_step (tmpbuf, 2, &v2_encoder_t::size_ready, false);
    }
}

void zmq::v2_encoder_t::size_ready ()
{
    //  Write message body into the buffer.
    next_step (in_progress->data (), in_progress->size (),
        &v2_encoder_t::message_ready, true);
}
