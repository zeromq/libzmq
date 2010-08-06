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

#include <new>

#include "../include/zmq.h"

#include "pipe.hpp"
#include "likely.hpp"

zmq::reader_t::reader_t (object_t *parent_, pipe_t *pipe_,
      uint64_t lwm_) :
    object_t (parent_),
    pipe (pipe_),
    writer (NULL),
    lwm (lwm_),
    msgs_read (0),
    sink (NULL),
    terminating (false)
{
    //  Note that writer is not set here. Writer will inform reader about its
    //  address once it is created (via set_writer method).
}

void zmq::reader_t::set_writer (writer_t *writer_)
{
    zmq_assert (!writer);
    writer = writer_;
}

zmq::reader_t::~reader_t ()
{
    //  Pipe as such is owned and deallocated by reader object.
    //  The point is that reader processes the last step of terminal
    //  handshaking (term_ack).
    zmq_assert (pipe);

    //  First delete all the unread messages in the pipe. We have to do it by
    //  hand because zmq_msg_t is a POD, not a class, so there's no associated
    //  destructor.
    zmq_msg_t msg;
    while (pipe->read (&msg))
       zmq_msg_close (&msg);

    delete pipe;
}

void zmq::reader_t::set_event_sink (i_reader_events *sink_)
{
    zmq_assert (!sink);
    sink = sink_;
}

bool zmq::reader_t::is_delimiter (zmq_msg_t &msg_)
{
    unsigned char *offset = 0;

    return msg_.content == (void*) (offset + ZMQ_DELIMITER);
}

bool zmq::reader_t::check_read ()
{
    if (unlikely (terminating))
        return false;

    //  Check if there's an item in the pipe.
    //  If not, deactivate the pipe.
    if (!pipe->check_read ()) {
        terminate ();
        return false;
    }

    //  If the next item in the pipe is message delimiter,
    //  initiate its termination.
    if (pipe->probe (is_delimiter)) {
        terminate ();
        return false;
    }

    return true;
}

bool zmq::reader_t::read (zmq_msg_t *msg_)
{
    if (unlikely (terminating))
        return false;

    if (!pipe->read (msg_))
        return false;

    //  If delimiter was read, start termination process of the pipe.
    unsigned char *offset = 0;
    if (msg_->content == (void*) (offset + ZMQ_DELIMITER)) {
        terminate ();
        return false;
    }

    if (!(msg_->flags & ZMQ_MSG_MORE))
        msgs_read++;

    if (lwm > 0 && msgs_read % lwm == 0)
        send_reader_info (writer, msgs_read);

    return true;
}

void zmq::reader_t::terminate ()
{
    //  If termination was already started by the peer, do nothing.
    if (terminating)
        return;

    terminating = true;
    send_pipe_term (writer);
}

void zmq::reader_t::process_revive ()
{
    //  Forward the event to the sink (either socket or session).
    sink->activated (this);
}

void zmq::reader_t::process_pipe_term_ack ()
{
    //  At this point writer may already be deallocated.
    //  For safety's sake drop the reference to it.
    writer = NULL;

    //  Notify owner about the termination.
    zmq_assert (sink);
    sink->terminated (this);

    //  Deallocate resources.
    delete this;
}

zmq::writer_t::writer_t (object_t *parent_, pipe_t *pipe_, reader_t *reader_,
      uint64_t hwm_, int64_t swap_size_) :
    object_t (parent_),
    pipe (pipe_),
    reader (reader_),
    hwm (hwm_),
    msgs_read (0),
    msgs_written (0),
    msg_store (NULL),
    extra_msg_flag (false),
    stalled (false),
    sink (NULL),
    terminating (false),
    pending_close (false)
{
    //  Inform reader about the writer.
    reader->set_writer (this);

    if (swap_size_ > 0) {
        msg_store = new (std::nothrow) msg_store_t (swap_size_);
        if (msg_store != NULL) {
            if (msg_store->init () < 0) {
                delete msg_store;
                msg_store = NULL;
            }
        }
    }
}

zmq::writer_t::~writer_t ()
{
    if (extra_msg_flag)
        zmq_msg_close (&extra_msg);

    delete msg_store;
}

void zmq::writer_t::set_event_sink (i_writer_events *sink_)
{
    zmq_assert (!sink);
    sink = sink_;
}

bool zmq::writer_t::check_write ()
{
    if (terminating)
        return false;

    if (pipe_full () && (msg_store == NULL || msg_store->full () || extra_msg_flag)) {
        stalled = true;
        return false;
    }

    return true;
}

bool zmq::writer_t::write (zmq_msg_t *msg_)
{
    if (terminating)
        return false;

    if (!check_write ())
        return false;

    if (pipe_full ()) {
        if (msg_store->store (msg_)) {
            if (!(msg_->flags & ZMQ_MSG_MORE))
                msg_store->commit ();
        } else {
            extra_msg = *msg_;
            extra_msg_flag = true;
        }
    }
    else {
        pipe->write (*msg_, msg_->flags & ZMQ_MSG_MORE);
        if (!(msg_->flags & ZMQ_MSG_MORE))
            msgs_written++;
    }

    return true;
}

void zmq::writer_t::rollback ()
{
    if (extra_msg_flag && extra_msg.flags & ZMQ_MSG_MORE) {
        zmq_msg_close (&extra_msg);
        extra_msg_flag = false;
    }

    if (msg_store != NULL)
        msg_store->rollback ();

    zmq_msg_t msg;
    //  Remove all incomplete messages from the pipe.
    while (pipe->unwrite (&msg)) {
        zmq_assert (msg.flags & ZMQ_MSG_MORE);
        zmq_msg_close (&msg);
        msgs_written--;
    }

    if (stalled && check_write ()) {
        stalled = false;
        zmq_assert (sink);
        sink->activated (this);
    }
}

void zmq::writer_t::flush ()
{
    if (!pipe->flush ())
        send_revive (reader);
}

void zmq::writer_t::terminate ()
{
    //  Prevent double termination.
    if (terminating)
        return;

    //  Rollback any unfinished messages.
    rollback ();

    if (msg_store == NULL || (msg_store->empty () && !extra_msg_flag))
        write_delimiter ();
    else
        pending_close = true;
}

void zmq::writer_t::write_delimiter ()
{
    //  Push delimiter into the pipe.
    //  Trick the compiler to belive that the tag is a valid pointer.
    zmq_msg_t msg;
    const unsigned char *offset = 0;
    msg.content = (void*) (offset + ZMQ_DELIMITER);
    msg.flags = 0;
    pipe->write (msg, false);
    flush ();
}

void zmq::writer_t::process_reader_info (uint64_t msgs_read_)
{
    zmq_msg_t msg;

    msgs_read = msgs_read_;
    if (msg_store) {

        //  Move messages from backing store into pipe.
        while (!pipe_full () && !msg_store->empty ()) {
            msg_store->fetch(&msg);
            //  Write message into the pipe.
            pipe->write (msg, msg.flags & ZMQ_MSG_MORE);
            if (!(msg.flags & ZMQ_MSG_MORE))
                msgs_written++;
        }

        if (extra_msg_flag) {
            if (!pipe_full ()) {
                pipe->write (extra_msg, extra_msg.flags & ZMQ_MSG_MORE);
                if (!(extra_msg.flags & ZMQ_MSG_MORE))
                    msgs_written++;
                extra_msg_flag = false;
            }
            else if (msg_store->store (&extra_msg)) {
                if (!(extra_msg.flags & ZMQ_MSG_MORE))
                    msg_store->commit ();
                extra_msg_flag = false;
            }
        }

        if (pending_close && msg_store->empty () && !extra_msg_flag) {
            write_delimiter ();
            pending_close = false;
        }

        flush ();
    }

    if (stalled) {
        stalled = false;
        zmq_assert (sink);
        sink->activated (this);
    }
}

void zmq::writer_t::process_pipe_term ()
{
    send_pipe_term_ack (reader);

    //  The above command allows reader to deallocate itself and the pipe.
    //  For safety's sake we'll drop the pointers here.
    reader = NULL;
    pipe = NULL;

    //  Notify owner about the termination.
    zmq_assert (sink);
    sink->terminated (this);

    //  Deallocate the resources.
    delete this;
}

bool zmq::writer_t::pipe_full ()
{
    return hwm > 0 && msgs_written - msgs_read == hwm;
}

void zmq::create_pipe (object_t *reader_parent_, object_t *writer_parent_,
    uint64_t hwm_, int64_t swap_size_, reader_t **reader_, writer_t **writer_)
{
    //  First compute the low water mark. Following point should be taken
    //  into consideration:
    //
    //  1. LWM has to be less than HWM.
    //  2. LWM cannot be set to very low value (such as zero) as after filling
    //     the queue it would start to refill only after all the messages are
    //     read from it and thus unnecessarily hold the progress back.
    //  3. LWM cannot be set to very high value (such as HWM-1) as it would
    //     result in lock-step filling of the queue - if a single message is
    //     read from a full queue, writer thread is resumed to write exactly one
    //     message to the queue and go back to sleep immediately. This would
    //     result in low performance.
    //
    //  Given the 3. it would be good to keep HWM and LWM as far apart as
    //  possible to reduce the thread switching overhead to almost zero,
    //  say HWM-LWM should be max_wm_delta.
    //
    //  That done, we still we have to account for the cases where
    //  HWM < max_wm_delta thus driving LWM to negative numbers.
    //  Let's make LWM 1/2 of HWM in such cases.
    uint64_t lwm = (hwm_ > max_wm_delta * 2) ?
        hwm_ - max_wm_delta : (hwm_ + 1) / 2;

    //  Create all three objects pipe consists of: the pipe per se, reader and
    //  writer. The pipe will be handled by reader and writer, its never passed
    //  to the user. Reader and writer are returned to the user.
    pipe_t *pipe = new (std::nothrow) pipe_t ();
    zmq_assert (pipe);
    *reader_ = new (std::nothrow) reader_t (reader_parent_, pipe, lwm);
    zmq_assert (*reader_);
    *writer_ = new (std::nothrow) writer_t (writer_parent_, pipe, *reader_,
        hwm_, swap_size_);
    zmq_assert (*writer_);
}
