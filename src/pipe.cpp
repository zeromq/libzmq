/*
    Copyright (c) 2007-2011 iMatix Corporation
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

#include <new>
#include <stddef.h>

#include "pipe.hpp"
#include "err.hpp"

int zmq::pipepair (class object_t *parents_ [2], class pipe_t* pipes_ [2],
    int hwms_ [2], bool delays_ [2])
{
    //   Creates two pipe objects. These objects are connected by two ypipes,
    //   each to pass messages in one direction.

    pipe_t::upipe_t *upipe1 = new (std::nothrow) pipe_t::upipe_t ();
    alloc_assert (upipe1);
    pipe_t::upipe_t *upipe2 = new (std::nothrow) pipe_t::upipe_t ();
    alloc_assert (upipe2);

    pipes_ [0] = new (std::nothrow) pipe_t (parents_ [0], upipe1, upipe2,
        hwms_ [1], hwms_ [0], delays_ [0]);
    alloc_assert (pipes_ [0]);
    pipes_ [1] = new (std::nothrow) pipe_t (parents_ [1], upipe2, upipe1,
        hwms_ [0], hwms_ [1], delays_ [1]);
    alloc_assert (pipes_ [1]);

    pipes_ [0]->set_peer (pipes_ [1]);
    pipes_ [1]->set_peer (pipes_ [0]);

    return 0;
}

zmq::pipe_t::pipe_t (object_t *parent_, upipe_t *inpipe_, upipe_t *outpipe_,
      int inhwm_, int outhwm_, bool delay_) :
    object_t (parent_),
    inpipe (inpipe_),
    outpipe (outpipe_),
    in_active (true),
    out_active (true),
    hwm (outhwm_),
    lwm (compute_lwm (inhwm_)),
    msgs_read (0),
    msgs_written (0),
    peers_msgs_read (0),
    peer (NULL),
    sink (NULL),
    terminating (false),
    term_recvd (false),
    delimited (false),
    delay (delay_)
{
}

zmq::pipe_t::~pipe_t ()
{
}

void zmq::pipe_t::set_peer (pipe_t *peer_)
{
    //  Peer can be set once only.
    zmq_assert (!peer);
    peer = peer_;
}

void zmq::pipe_t::set_event_sink (i_pipe_events *sink_)
{
    // Sink can be set once only.
    zmq_assert (!sink);
    sink = sink_;
}

bool zmq::pipe_t::check_read ()
{
    if (unlikely (!in_active))
        return false;

    //  Check if there's an item in the pipe.
    if (!inpipe->check_read ()) {
        in_active = false;
        return false;
    }

    //  If the next item in the pipe is message delimiter,
    //  initiate termination process.
    if (inpipe->probe (is_delimiter)) {
        msg_t msg;
        bool ok = inpipe->read (&msg);
        zmq_assert (ok);
        delimited = true;

        //  If pipe_term was already received but wasn't processed because
        //  of pending messages, we can ack it now.
        if (terminating)
            send_pipe_term_ack (peer);

        return false;
    }

    return true;
}

bool zmq::pipe_t::read (msg_t *msg_)
{
    if (unlikely (!in_active))
        return false;

    if (!inpipe->read (msg_)) {
        in_active = false;
        return false;
    }

    //  If delimiter was read, start termination process of the pipe.
    if (msg_->is_delimiter ()) {
        delimited = true;

        //  If pipe_term was already received but wasn't processed because
        //  of pending messages, we can ack it now.
        if (terminating)
            send_pipe_term_ack (peer);

        return false;
    }

    if (!(msg_->flags () & msg_t::more))
        msgs_read++;

    if (lwm > 0 && msgs_read % lwm == 0)
        send_activate_write (peer, msgs_read);

    return true;
}

bool zmq::pipe_t::check_write (msg_t *msg_)
{
    if (unlikely (!out_active))
        return false;

    bool full = hwm > 0 && msgs_written - peers_msgs_read == uint64_t (hwm);

    if (unlikely (full)) {
        out_active = false;
        return false;
    }

    return true;
}

bool zmq::pipe_t::write (msg_t *msg_)
{
    if (unlikely (!check_write (msg_)))
        return false;

    outpipe->write (*msg_, msg_->flags () & msg_t::more);
    if (!(msg_->flags () & msg_t::more))
        msgs_written++;

    return true;
}

void zmq::pipe_t::rollback ()
{
    //  Remove incomplete message from the outbound pipe.
    msg_t msg;
    while (outpipe->unwrite (&msg)) {
        zmq_assert (msg.flags () & msg_t::more);
        int rc = msg.close ();
        errno_assert (rc == 0);
    }
}

void zmq::pipe_t::flush ()
{
    if (!outpipe->flush ())
        send_activate_read (peer);
}

void zmq::pipe_t::process_activate_read ()
{
    if (!in_active && !terminating) {
        in_active = true;
        sink->read_activated (this);
    }
}

void zmq::pipe_t::process_activate_write (uint64_t msgs_read_)
{
    //  Remember the peers's message sequence number.
    peers_msgs_read = msgs_read_;

    if (!out_active && !terminating) {
        out_active = true;
        sink->write_activated (this);
    }
}

void zmq::pipe_t::process_pipe_term ()
{
    term_recvd = true;

    //  We can proceed with the termination if one of the following is true:
    //  1. User asked this side of pipe to terminate already.
    //  2. Waiting for pending messages in not required.
    //  3. Delimiter was already received.
    if (terminating || !delay || delimited) {
        terminating = true;
        send_pipe_term_ack (peer);
    }
}

void zmq::pipe_t::process_pipe_term_ack ()
{
    //  Notify the user that all the references to the pipe should be dropped.
    zmq_assert (sink);
    sink->terminated (this);

    //  If the peer haven't asked for the termination itself, we have to
    //  ack the ack, so that it can deallocate properly.
    if (!term_recvd)
        send_pipe_term_ack (peer);

    //  We'll deallocate the inbound pipe, the peer will deallocate the outbound
    //  pipe (which is an inbound pipe from its point of view).
    //  First, delete all the unread messages in the pipe. We have to do it by
    //  hand because msg_t doesn't have automatic destructor. Then deallocate
    //  the ypipe itself.
    msg_t msg;
    while (inpipe->read (&msg)) {
       int rc = msg.close ();
       errno_assert (rc == 0);
    }
    delete inpipe;

    //  Deallocate the pipe object
    delete this;
}

void zmq::pipe_t::terminate ()
{
    //  Prevent double termination.
    if (terminating)
        return;
    terminating = true;

    //  Stop inbound and outbound flow of messages.
    in_active = false;
    out_active = false;

    //  Rollback any unfinished outbound messages.
    rollback ();

    //  Push delimiter into the outbound pipe. Note that watermarks are not
    //  checked thus the delimiter can be written even though the pipe is full.
    msg_t msg;
    msg.init_delimiter ();
    outpipe->write (msg, false);
    flush ();

    //  Start the termination handshaking.
    send_pipe_term (peer);
}

bool zmq::pipe_t::is_delimiter (msg_t &msg_)
{
    return msg_.is_delimiter ();
}

int zmq::pipe_t::compute_lwm (int hwm_)
{
    //  Compute the low water mark. Following point should be taken
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
    int result = (hwm_ > max_wm_delta * 2) ?
        hwm_ - max_wm_delta : (hwm_ + 1) / 2;

    return result;
}
