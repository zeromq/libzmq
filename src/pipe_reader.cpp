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

#include "../include/zmq.h"

#include "pipe_reader.hpp"
#include "pipe.hpp"
#include "err.hpp"
#include "i_mux.hpp"

zmq::pipe_reader_t::pipe_reader_t (object_t *parent_, pipe_t *pipe_,
      uint64_t hwm_, uint64_t lwm_) :
    object_t (parent_),
    pipe (pipe_),
    peer (NULL),
    mux (NULL),
    index (-1),
    hwm (hwm_),
    lwm (lwm_),
    head (0),
    tail (0),
    last_sent_head (0)
{
}

void zmq::pipe_reader_t::set_peer (object_t *peer_)
{
    peer = peer_;
}

zmq::pipe_reader_t::~pipe_reader_t ()
{
}

void zmq::pipe_reader_t::set_mux (i_mux *mux_)
{
    mux = mux_;
}

void zmq::pipe_reader_t::set_index (int index_)
{
    index = index_;
}

int zmq::pipe_reader_t::get_index ()
{
    return index;
}

void zmq::pipe_reader_t::process_tail (uint64_t bytes_)
{
    tail = bytes_;
    mux->reactivate (this);
}

bool zmq::pipe_reader_t::read (struct zmq_msg *msg_)
{
    //  Read a message.
    if (!pipe->read (msg_)) {
        mux->deactivate (this);
        return false;
    }

    //  If successfull, adjust the head of the pipe.
    head += zmq_msg_size (msg_);

    //  If pipe writer wasn't notified about the head position for long enough,
    //  notify it.
    if (head - last_sent_head >= hwm - lwm) {
        send_head (peer, head);
        last_sent_head = head;
    }

    if (zmq_msg_type (msg_) == ZMQ_DELIMITER) {

        //  Detach the pipe from the mux and send termination request to
        //  the pipe writer.
        mux->detach_pipe (this);
        mux = NULL;
        send_terminate (peer);
        return false;
    }

    return true;
}

void zmq::pipe_reader_t::terminate ()
{
    //  Detach the pipe from the mux and send termination request to
    //  the pipe writer.
    if (mux) {
        mux->detach_pipe (this);
        mux = NULL;
    }
    send_terminate (peer);
}

void zmq::pipe_reader_t::process_terminate_ack ()
{
    //  Ask dispatcher to deallocate the pipe.
    destroy_pipe (pipe);
}
