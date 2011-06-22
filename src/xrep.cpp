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

#include "xrep.hpp"
#include "pipe.hpp"
#include "wire.hpp"
#include "random.hpp"
#include "err.hpp"

zmq::xrep_t::xrep_t (class ctx_t *parent_, uint32_t tid_) :
    socket_base_t (parent_, tid_),
    current_in (0),
    prefetched (false),
    more_in (false),
    current_out (NULL),
    more_out (false)
{
    options.type = ZMQ_XREP;

    //  Start the peer ID sequence from a random point.
    generate_random (&next_peer_id, sizeof (next_peer_id));
}

zmq::xrep_t::~xrep_t ()
{
    zmq_assert (inpipes.empty ());
    zmq_assert (outpipes.empty ());
}

void zmq::xrep_t::xattach_pipe (pipe_t *pipe_, const blob_t &peer_identity_)
{
    zmq_assert (pipe_);

    //  Generate a new peer ID. Take care to avoid duplicates.
    outpipes_t::iterator it = outpipes.lower_bound (next_peer_id);
    if (!outpipes.empty ()) {
        while (true) {
            if (it == outpipes.end ())
                it = outpipes.begin ();
            if (it->first != next_peer_id)
                break;
            ++next_peer_id;
            ++it;
        }
    }

    //  Add the pipe to the map out outbound pipes.
    outpipe_t outpipe = {pipe_, true};
    bool ok = outpipes.insert (outpipes_t::value_type (
        next_peer_id, outpipe)).second;
    zmq_assert (ok);

    //  Add the pipe to the list of inbound pipes.
    inpipe_t inpipe = {pipe_, next_peer_id, true};
    inpipes.push_back (inpipe);

    //  Advance next peer ID so that if new connection is dropped shortly after
    //  its creation we don't accidentally get two subsequent peers with
    //  the same ID.
    ++next_peer_id;
}

void zmq::xrep_t::xterminated (pipe_t *pipe_)
{
    for (inpipes_t::iterator it = inpipes.begin (); it != inpipes.end ();
          ++it) {
        if (it->pipe == pipe_) {
            if ((inpipes_t::size_type) (it - inpipes.begin ()) < current_in)
                current_in--;
            inpipes.erase (it);
            if (current_in >= inpipes.size ())
                current_in = 0;
            goto clean_outpipes;
        }
    }
    zmq_assert (false);

clean_outpipes:
    for (outpipes_t::iterator it = outpipes.begin ();
          it != outpipes.end (); ++it) {
        if (it->second.pipe == pipe_) {
            outpipes.erase (it);
            if (pipe_ == current_out)
                current_out = NULL;
            return;
        }
    }
    zmq_assert (false);
}

void zmq::xrep_t::xread_activated (pipe_t *pipe_)
{
    for (inpipes_t::iterator it = inpipes.begin (); it != inpipes.end ();
          ++it) {
        if (it->pipe == pipe_) {
            zmq_assert (!it->active);
            it->active = true;
            return;
        }
    }
    zmq_assert (false);
}

void zmq::xrep_t::xwrite_activated (pipe_t *pipe_)
{
    for (outpipes_t::iterator it = outpipes.begin ();
          it != outpipes.end (); ++it) {
        if (it->second.pipe == pipe_) {
            zmq_assert (!it->second.active);
            it->second.active = true;
            return;
        }
    }
    zmq_assert (false);
}

int zmq::xrep_t::xsend (msg_t *msg_, int flags_)
{
    //  If this is the first part of the message it's the ID of the
    //  peer to send the message to.
    if (!more_out) {
        zmq_assert (!current_out);

        //  If we have malformed message (prefix with no subsequent message)
        //  then just silently ignore it.
        //  TODO: The connections should be killed instead.
        if (msg_->flags () & msg_t::label) {

            more_out = true;

            //  Find the pipe associated with the peer ID stored in the prefix.
            //  If there's no such pipe just silently ignore the message.
            zmq_assert (msg_->size () == 4);
            uint32_t peer_id = get_uint32 ((unsigned char*) msg_->data ());
            outpipes_t::iterator it = outpipes.find (peer_id);

            if (it != outpipes.end ()) {
                current_out = it->second.pipe;
                msg_t empty;
                int rc = empty.init ();
                errno_assert (rc == 0);
                if (!current_out->check_write (&empty)) {
                    it->second.active = false;
                    more_out = false;
                    current_out = NULL;
                    rc = empty.close ();
                    errno_assert (rc == 0);
                    errno = EAGAIN;
                    return -1;
                }
                rc = empty.close ();
                errno_assert (rc == 0);
            }
        }

        int rc = msg_->close ();
        errno_assert (rc == 0);
        rc = msg_->init ();
        errno_assert (rc == 0);
        return 0;
    }

    //  Check whether this is the last part of the message.
    more_out = msg_->flags () & (msg_t::more | msg_t::label);

    //  Push the message into the pipe. If there's no out pipe, just drop it.
    if (current_out) {
        bool ok = current_out->write (msg_);
        zmq_assert (ok);
        if (!more_out) {
            current_out->flush ();
            current_out = NULL;
        }
    }
    else {
        int rc = msg_->close ();
        errno_assert (rc == 0);
    }

    //  Detach the message from the data buffer.
    int rc = msg_->init ();
    errno_assert (rc == 0);

    return 0;
}

int zmq::xrep_t::xrecv (msg_t *msg_, int flags_)
{
    //  If there is a prefetched message, return it.
    if (prefetched) {
        int rc = msg_->move (prefetched_msg);
        errno_assert (rc == 0);
        more_in = msg_->flags () & (msg_t::more | msg_t::label);
        prefetched = false;
        return 0;
    }

    //  Deallocate old content of the message.
    int rc = msg_->close ();
    errno_assert (rc == 0);

    //  If we are in the middle of reading a message, just grab next part of it.
    if (more_in) {
        zmq_assert (inpipes [current_in].active);
        bool fetched = inpipes [current_in].pipe->read (msg_);
        zmq_assert (fetched);
        more_in = msg_->flags () & (msg_t::more | msg_t::label);
        if (!more_in) {
            current_in++;
            if (current_in >= inpipes.size ())
                current_in = 0;
        }
        return 0;
    }

    //  Round-robin over the pipes to get the next message.
    for (inpipes_t::size_type count = inpipes.size (); count != 0; count--) {

        //  Try to fetch new message.
        if (inpipes [current_in].active)
            prefetched = inpipes [current_in].pipe->read (&prefetched_msg);

        //  If we have a message, create a prefix and return it to the caller.
        if (prefetched) {
            int rc = msg_->init_size (4);
            errno_assert (rc == 0);
            put_uint32 ((unsigned char*) msg_->data (),
                inpipes [current_in].peer_id);
            msg_->set_flags (msg_t::label);
            return 0;
        }

        //  If me don't have a message, mark the pipe as passive and
        //  move to next pipe.
        inpipes [current_in].active = false;
        current_in++;
        if (current_in >= inpipes.size ())
            current_in = 0;
    }

    //  No message is available. Initialise the output parameter
    //  to be a 0-byte message.
    rc = msg_->init ();
    errno_assert (rc == 0);
    errno = EAGAIN;
    return -1;
}

int zmq::xrep_t::rollback (void)
{
    if (current_out) {
        current_out->rollback ();
        current_out = NULL;
        more_out = false;
    }
    return 0;
}

bool zmq::xrep_t::xhas_in ()
{
    //  There are subsequent parts of the partly-read message available.
    if (prefetched || more_in)
        return true;

    //  Note that messing with current doesn't break the fairness of fair
    //  queueing algorithm. If there are no messages available current will
    //  get back to its original value. Otherwise it'll point to the first
    //  pipe holding messages, skipping only pipes with no messages available.
    for (inpipes_t::size_type count = inpipes.size (); count != 0; count--) {
        if (inpipes [current_in].active &&
              inpipes [current_in].pipe->check_read ())
            return true;

        //  If me don't have a message, mark the pipe as passive and
        //  move to next pipe.
        inpipes [current_in].active = false;
        current_in++;
        if (current_in >= inpipes.size ())
            current_in = 0;
    }

    return false;
}

bool zmq::xrep_t::xhas_out ()
{
    //  In theory, XREP socket is always ready for writing. Whether actual
    //  attempt to write succeeds depends on whitch pipe the message is going
    //  to be routed to.
    return true;
}



