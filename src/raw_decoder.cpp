/*
    Copyright (c) 2007-2013 Contributors as noted in the AUTHORS file

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

#include "platform.hpp"
#ifdef ZMQ_HAVE_WINDOWS
#include "windows.hpp"
#endif

#include "raw_decoder.hpp"
#include "likely.hpp"
#include "wire.hpp"
#include "err.hpp"

zmq::raw_decoder_t::raw_decoder_t (size_t bufsize_,
      int64_t maxmsgsize_, i_msg_sink *msg_sink_) :
    decoder_base_t <raw_decoder_t> (bufsize_),
    msg_sink (msg_sink_),
    maxmsgsize (maxmsgsize_)
{
    int rc = in_progress.init ();
    errno_assert (rc == 0);
}

zmq::raw_decoder_t::~raw_decoder_t ()
{
    int rc = in_progress.close ();
    errno_assert (rc == 0);
}

void zmq::raw_decoder_t::set_msg_sink (i_msg_sink *msg_sink_)
{
    msg_sink = msg_sink_;
}

bool zmq::raw_decoder_t::stalled ()
{
    return false;
}

bool zmq::raw_decoder_t::message_ready_size (size_t msg_sz)
{
    int rc = in_progress.init_size (msg_sz);
    if (rc != 0) {
        errno_assert (errno == ENOMEM);
        rc = in_progress.init ();
        errno_assert (rc == 0);
        decoding_error ();
        return false;
    }

    next_step (in_progress.data (), in_progress.size (),
        &raw_decoder_t::raw_message_ready);

    return true;
}

bool zmq::raw_decoder_t::raw_message_ready ()
{
    zmq_assert (in_progress.size ());
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

    // NOTE: This is just to break out of process_buffer
    // raw_message_ready should never get called in state machine w/o
    // message_ready_size from stream_engine.
    next_step (in_progress.data (), 1,
        &raw_decoder_t::raw_message_ready);

    return true;
}
