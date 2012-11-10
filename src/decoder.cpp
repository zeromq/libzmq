/*
    Copyright (c) 2009-2011 250bpm s.r.o.
    Copyright (c) 2007-2009 iMatix Corporation
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

#include <stdlib.h>
#include <string.h>
#include <limits>

#include "platform.hpp"
#if defined ZMQ_HAVE_WINDOWS
#include "windows.hpp"
#endif

#include "decoder.hpp"
#include "i_msg_sink.hpp"
#include "likely.hpp"
#include "wire.hpp"
#include "err.hpp"

zmq::decoder_t::decoder_t (size_t bufsize_, int64_t maxmsgsize_) :
    decoder_base_t <decoder_t> (bufsize_),
    msg_sink (NULL),
    maxmsgsize (maxmsgsize_)
{
    int rc = in_progress.init ();
    errno_assert (rc == 0);

    //  At the beginning, read one byte and go to one_byte_size_ready state.
    next_step (tmpbuf, 1, &decoder_t::one_byte_size_ready);
}

zmq::decoder_t::~decoder_t ()
{
    int rc = in_progress.close ();
    errno_assert (rc == 0);
}

void zmq::decoder_t::set_msg_sink (i_msg_sink *msg_sink_)
{
    msg_sink = msg_sink_;
}

bool zmq::decoder_t::one_byte_size_ready ()
{
    //  First byte of size is read. If it is 0xff read 8-byte size.
    //  Otherwise allocate the buffer for message data and read the
    //  message data into it.
    if (*tmpbuf == 0xff)
        next_step (tmpbuf, 8, &decoder_t::eight_byte_size_ready);
    else {

        //  There has to be at least one byte (the flags) in the message).
        if (!*tmpbuf) {
            decoding_error ();
            return false;
        }

        //  in_progress is initialised at this point so in theory we should
        //  close it before calling zmq_msg_init_size, however, it's a 0-byte
        //  message and thus we can treat it as uninitialised...
        int rc;
        if (maxmsgsize >= 0 && (int64_t) (*tmpbuf - 1) > maxmsgsize) {
            rc = -1;
            errno = ENOMEM;
        }
        else
            rc = in_progress.init_size (*tmpbuf - 1);
        if (rc != 0 && errno == ENOMEM) {
            rc = in_progress.init ();
            errno_assert (rc == 0);
            decoding_error ();
            return false;
        }
        errno_assert (rc == 0);

        next_step (tmpbuf, 1, &decoder_t::flags_ready);
    }
    return true;
}

bool zmq::decoder_t::eight_byte_size_ready ()
{
    //  8-byte payload length is read. Allocate the buffer
    //  for message body and read the message data into it.
    const uint64_t payload_length = get_uint64 (tmpbuf);

    //  There has to be at least one byte (the flags) in the message).
    if (payload_length == 0) {
        decoding_error ();
        return false;
    }

    //  Message size must not exceed the maximum allowed size.
    if (maxmsgsize >= 0 && payload_length - 1 > (uint64_t) maxmsgsize) {
        decoding_error ();
        return false;
    }

    //  Message size must fit within range of size_t data type.
    if (payload_length - 1 > std::numeric_limits <size_t>::max ()) {
        decoding_error ();
        return false;
    }

    const size_t msg_size = static_cast <size_t> (payload_length - 1);

    //  in_progress is initialised at this point so in theory we should
    //  close it before calling init_size, however, it's a 0-byte
    //  message and thus we can treat it as uninitialised...
    int rc = in_progress.init_size (msg_size);
    if (rc != 0) {
        errno_assert (errno == ENOMEM);
        rc = in_progress.init ();
        errno_assert (rc == 0);
        decoding_error ();
        return false;
    }

    next_step (tmpbuf, 1, &decoder_t::flags_ready);
    return true;
}

bool zmq::decoder_t::flags_ready ()
{
    //  Store the flags from the wire into the message structure.
    in_progress.set_flags (tmpbuf [0] & msg_t::more);

    next_step (in_progress.data (), in_progress.size (),
        &decoder_t::message_ready);

    return true;
}

bool zmq::decoder_t::message_ready ()
{
    //  Message is completely read. Push it further and start reading
    //  new message. (in_progress is a 0-byte message after this point.)
    if (unlikely (!msg_sink))
        return false;
    int rc = msg_sink->push_msg (&in_progress);
    if (unlikely (rc != 0)) {
        if (errno != EAGAIN)
            decoding_error ();
        return false;
    }

    next_step (tmpbuf, 1, &decoder_t::one_byte_size_ready);
    return true;
}
