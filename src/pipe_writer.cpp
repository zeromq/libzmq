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

#include "../include/zs.h"

#include "pipe_writer.hpp"
#include "pipe.hpp"
#include "i_demux.hpp"

zs::pipe_writer_t::pipe_writer_t (object_t *parent_, pipe_t *pipe_,
      object_t *peer_, uint64_t hwm_, uint64_t lwm_) :
    object_t (parent_),
    pipe (pipe_),
    peer (peer_),
    demux (NULL),
    index (-1),
    hwm (hwm_),
    lwm (lwm_),
    head (0),
    tail (0)
{
}

zs::pipe_writer_t::~pipe_writer_t ()
{
}

void zs::pipe_writer_t::set_demux (i_demux *demux_)
{
    demux = demux_;
}

void zs::pipe_writer_t::set_index (int index_)
{
    index = index_;
}

int zs::pipe_writer_t::get_index ()
{
    return index;
}

bool zs::pipe_writer_t::write (zs_msg *msg_)
{
    size_t msg_size = zs_msg_size (msg_);

    //  If message won't fit into the in-memory pipe, there's no way
    //  to pass it further.
    //  TODO: It should be discarded and 'oversized' notification should be
    //        placed into the pipe.
    zs_assert (!hwm || msg_size <= hwm);

    //  If there's not enough space in the pipe at the moment, return false.
    if (hwm && tail + msg_size - head > hwm)
        return false;

    //  Write the message to the pipe and adjust tail position.
    pipe->write (*msg_);
    flush ();
    tail += msg_size;

    return true;
}

void zs::pipe_writer_t::flush ()
{
    if (!pipe->flush ())
        send_tail (peer, tail);
}

void zs::pipe_writer_t::process_head (uint64_t bytes_)
{
    head = bytes_;
}

void zs::pipe_writer_t::terminate ()
{
    //  Disconnect from the associated demux.
    if (demux) {
        demux->detach_pipe (this);
        demux = NULL;
    }

    //  Push the delimiter to the pipe. Delimiter is a notification for pipe
    //  reader that there will be no more messages in the pipe.
    zs_msg delimiter;
    delimiter.content = (zs_msg_content*) ZS_DELIMITER;
    delimiter.shared = false;
    delimiter.vsm_size = 0;
    pipe->write (delimiter);
    flush ();
}

void zs::pipe_writer_t::process_terminate ()
{
    //  Disconnect from the associated demux.
    if (demux) {
        demux->detach_pipe (this);
        demux = NULL;
    }

    //  Send termination acknowledgement to the pipe reader.
    send_terminate_ack (peer);
}
