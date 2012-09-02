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

#include "encoder.hpp"
#include "i_msg_source.hpp"
#include "likely.hpp"
#include "wire.hpp"

zmq::encoder_t::encoder_t (size_t bufsize_) :
    encoder_base_t <encoder_t> (bufsize_),
    msg_source (NULL)
{
    int rc = in_progress.init ();
    errno_assert (rc == 0);

    //  Write 0 bytes to the batch and go to message_ready state.
    next_step (NULL, 0, &encoder_t::message_ready, true);
}

zmq::encoder_t::~encoder_t ()
{
    int rc = in_progress.close ();
    errno_assert (rc == 0);
}

void zmq::encoder_t::set_msg_source (i_msg_source *msg_source_)
{
    msg_source = msg_source_;
}

bool zmq::encoder_t::size_ready ()
{
    //  Write message body into the buffer.
    next_step (in_progress.data (), in_progress.size (),
        &encoder_t::message_ready, !(in_progress.flags () & msg_t::more));
    return true;
}

bool zmq::encoder_t::message_ready ()
{
    //  Destroy content of the old message.
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
    if (unlikely (rc != 0)) {
        errno_assert (errno == EAGAIN);
        rc = in_progress.init ();
        errno_assert (rc == 0);
        return false;
    }

    //  Get the message size.
    size_t size = in_progress.size ();

    //  Account for the 'flags' byte.
    size++;

    //  For messages less than 255 bytes long, write one byte of message size.
    //  For longer messages write 0xff escape character followed by 8-byte
    //  message size. In both cases 'flags' field follows.
    if (size < 255) {
        tmpbuf [0] = (unsigned char) size;
        tmpbuf [1] = (in_progress.flags () & msg_t::more);
        next_step (tmpbuf, 2, &encoder_t::size_ready, false);
    }
    else {
        tmpbuf [0] = 0xff;
        put_uint64 (tmpbuf + 1, size);
        tmpbuf [9] = (in_progress.flags () & msg_t::more);
        next_step (tmpbuf, 10, &encoder_t::size_ready, false);
    }
    return true;
}
