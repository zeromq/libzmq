/*
    Copyright (c) 2007-2010 iMatix Corporation

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

#include "pipe.hpp"

zmq::reader_t::reader_t (object_t *parent_,
      uint64_t hwm_, uint64_t lwm_) :
    object_t (parent_),
    pipe (NULL),
    peer (NULL),
    hwm (hwm_),
    lwm (lwm_),
    msgs_read (0),
    endpoint (NULL)
{
    //  Adjust lwm and hwm.
    if (lwm == 0 || lwm > hwm)
        lwm = hwm;
}

zmq::reader_t::~reader_t ()
{
    if (pipe)
        unregister_pipe (pipe);
}

void zmq::reader_t::set_pipe (pipe_t *pipe_)
{
    zmq_assert (!pipe);
    pipe = pipe_;
    peer = &pipe->writer;
    register_pipe (pipe);
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

    if (!(msg_->flags & ZMQ_MSG_MORE))
        msgs_read++;

    if (lwm > 0 && msgs_read % lwm == 0)
        send_reader_info (peer, msgs_read);

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

zmq::writer_t::writer_t (object_t *parent_,
      uint64_t hwm_, uint64_t lwm_) :
    object_t (parent_),
    pipe (NULL),
    peer (NULL),
    hwm (hwm_),
    lwm (lwm_),
    msgs_read (0),
    msgs_written (0),
    stalled (false),
    endpoint (NULL)
{
    //  Adjust lwm and hwm.
    if (lwm == 0 || lwm > hwm)
        lwm = hwm;
}

void zmq::writer_t::set_endpoint (i_endpoint *endpoint_)
{
    endpoint = endpoint_;
}

zmq::writer_t::~writer_t ()
{
}

void zmq::writer_t::set_pipe (pipe_t *pipe_)
{
    zmq_assert (!pipe);
    pipe = pipe_;
    peer = &pipe->reader;
}

bool zmq::writer_t::check_write ()
{
    if (pipe_full ()) {
        stalled = true;
        return false;
    }

    return true;
}

bool zmq::writer_t::write (zmq_msg_t *msg_)
{
    if (pipe_full ()) {
        stalled = true;
        return false;
    }

    pipe->write (*msg_, msg_->flags & ZMQ_MSG_MORE);
    if (!(msg_->flags & ZMQ_MSG_MORE))
        msgs_written++;
    return true;
}

void zmq::writer_t::rollback ()
{
    zmq_msg_t msg;

    //  Remove all incomplete messages from the pipe.
    while (pipe->unwrite (&msg)) {
        zmq_assert (msg.flags & ZMQ_MSG_MORE);
        zmq_msg_close (&msg);
        msgs_written--;
    }

    if (stalled && endpoint != NULL && !pipe_full()) {
        stalled = false;
        endpoint->revive (this);
    }
}

void zmq::writer_t::flush ()
{
    if (!pipe->flush ())
        send_revive (peer);
}

void zmq::writer_t::term ()
{
    endpoint = NULL;

    //  Rollback any unfinished messages.
    rollback ();

    //  Push delimiter into the pipe.
    //  Trick the compiler to belive that the tag is a valid pointer.
    zmq_msg_t msg;
    const unsigned char *offset = 0;
    msg.content = (void*) (offset + ZMQ_DELIMITER);
    msg.flags = 0;
    pipe->write (msg, false);
    pipe->flush ();
}

void zmq::writer_t::process_reader_info (uint64_t msgs_read_)
{
    msgs_read = msgs_read_;
    if (stalled && endpoint != NULL) {
        stalled = false;
        endpoint->revive (this);
    }
}

void zmq::writer_t::process_pipe_term ()
{
    if (endpoint)
        endpoint->detach_outpipe (this);

    reader_t *p = peer;
    peer = NULL;
    send_pipe_term_ack (p);
}

bool zmq::writer_t::pipe_full ()
{
    return hwm > 0 && msgs_written - msgs_read == hwm;
}

zmq::pipe_t::pipe_t (object_t *reader_parent_, object_t *writer_parent_,
      uint64_t hwm_) :
    reader (reader_parent_, hwm_, compute_lwm (hwm_)),
    writer (writer_parent_, hwm_, compute_lwm (hwm_))
{
    reader.set_pipe (this);
    writer.set_pipe (this);
}

zmq::pipe_t::~pipe_t ()
{
    //  Deallocate all the unread messages in the pipe. We have to do it by
    //  hand because zmq_msg_t is a POD, not a class, so there's no associated
    //  destructor.
    zmq_msg_t msg;
    while (read (&msg))
       zmq_msg_close (&msg);
}

uint64_t zmq::pipe_t::compute_lwm (uint64_t hwm_)
{
   //  Following point should be taken into consideration when computing
   //  low watermark:
   //
   //  1. LWM has to be less than HWM.
   //  2. LWM cannot be set to very low value (such as zero) as after filling
   //     the queue it would start to refill only after all the messages are
   //     read from it and thus unnecessarily hold the progress back.
   //  3. LWM cannot be set to very high value (such as HWM-1) as it would
   //     result in lock-step filling of the queue - if a single message is read
   //     from a full queue, writer thread is resumed to write exactly one
   //     message to the queue and go back to sleep immediately. This would
   //     result in low performance.
   //
   //  Given the 3. it would be good to keep HWM and LWM as far apart as
   //  possible to reduce the thread switching overhead to almost zero,
   //  say HWM-LWM should be 500 (max_wm_delta).
   //
   //  That done, we still we have to account for the cases where HWM<500 thus
   //  driving LWM to negative numbers. Let's make LWM 1/2 of HWM in such cases.

    if (hwm_ > max_wm_delta * 2)
        return hwm_ - max_wm_delta;
    else
        return hwm_ / 2;
}

