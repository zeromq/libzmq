/*
    Copyright (c) 2007-2012 iMatix Corporation
    Copyright (c) 2009-2011 250bpm s.r.o.
    Copyright (c) 2011 VMware, Inc.
    Copyright (c) 2007-2012 Other contributors as noted in the AUTHORS file

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
#include "raw_encoder.hpp"
#include "i_msg_source.hpp"
#include "likely.hpp"
#include "wire.hpp"

zmq::raw_encoder_t::raw_encoder_t (size_t bufsize_, i_msg_source *msg_source_) :
    encoder_base_t <raw_encoder_t> (bufsize_),
    msg_source (msg_source_)
{
    int rc = in_progress.init ();
    errno_assert (rc == 0);

    //  Write 0 bytes to the batch and go to message_ready state.
    next_step (NULL, 0, &raw_encoder_t::raw_message_ready, true);
}

zmq::raw_encoder_t::~raw_encoder_t ()
{
    int rc = in_progress.close ();
    errno_assert (rc == 0);
}

void zmq::raw_encoder_t::set_msg_source (i_msg_source *msg_source_)
{
    msg_source = msg_source_;
}

bool zmq::raw_encoder_t::raw_message_size_ready ()
{
    //  Write message body into the buffer.
    next_step (in_progress.data (), in_progress.size (),
        &raw_encoder_t::raw_message_ready, !(in_progress.flags () & msg_t::more));
    return true;
}

bool zmq::raw_encoder_t::raw_message_ready ()
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

    in_progress.reset_flags(0xff);
    next_step (NULL, 0, &raw_encoder_t::raw_message_size_ready, true);

    return true;
}
