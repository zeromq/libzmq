/*
    Copyright (c) 2007-2012 iMatix Corporation
    Copyright (c) 2009-2011 250bpm s.r.o.
    Copyright (c) 2011 VMware, Inc.
    Copyright (c) 2007-2011 Other contributors as noted in the AUTHORS file

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

#include "v1_protocol.hpp"
#include "v1_encoder.hpp"
#include "likely.hpp"
#include "wire.hpp"

zmq::v1_encoder_t::v1_encoder_t (size_t bufsize_, i_msg_source *msg_source_) :
    encoder_base_t <v1_encoder_t> (bufsize_),
    msg_source (msg_source_)
{
    int rc = in_progress.init ();
    errno_assert (rc == 0);

    //  Write 0 bytes to the batch and go to message_ready state.
    next_step (NULL, 0, &v1_encoder_t::message_ready, true);
}

zmq::v1_encoder_t::~v1_encoder_t ()
{
    int rc = in_progress.close ();
    errno_assert (rc == 0);
}

void zmq::v1_encoder_t::set_msg_source (i_msg_source *msg_source_)
{
    msg_source = msg_source_;
}

bool zmq::v1_encoder_t::message_ready ()
{
    //  Release the content of the old message.
    int rc = in_progress.close ();
    errno_assert (rc == 0);

    //  Read new message. If there is none, return false.
    //  Note that new state is set only if write is successful. That way
    //  unsuccessful write will cause retry on the next state machine
    //  invocation.
    if (unlikely (!msg_source)) {
        rc = in_progress.init ();
        errno_assert (rc == 0);
        return false;
    }

    rc = msg_source->pull_msg (&in_progress);
    if (unlikely (rc)) {
        errno_assert (errno == EAGAIN);
        rc = in_progress.init ();
        errno_assert (rc == 0);
        return false;
    }

    //  Encode flags.
    unsigned char &protocol_flags = tmpbuf [0];
    protocol_flags = 0;
    if (in_progress.flags () & msg_t::more)
        protocol_flags |= v1_protocol_t::more_flag;
    if (in_progress.size () > 255)
        protocol_flags |= v1_protocol_t::large_flag;

    //  Encode the message length. For messages less then 256 bytes,
    //  the length is encoded as 8-bit unsigned integer. For larger
    //  messages, 64-bit unsigned integer in network byte order is used.
    const size_t size = in_progress.size ();
    if (unlikely (size > 255)) {
        put_uint64 (tmpbuf + 1, size);
        next_step (tmpbuf, 9, &v1_encoder_t::size_ready, false);
    }
    else {
        tmpbuf [1] = static_cast <uint8_t> (size);
        next_step (tmpbuf, 2, &v1_encoder_t::size_ready, false);
    }
    return true;
}

bool zmq::v1_encoder_t::size_ready ()
{
    //  Write message body into the buffer.
    next_step (in_progress.data (), in_progress.size (),
        &v1_encoder_t::message_ready, !(in_progress.flags () & msg_t::more));
    return true;
}
