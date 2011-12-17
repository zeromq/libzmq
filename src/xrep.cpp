/*
    Copyright (c) 2009-2011 250bpm s.r.o.
    Copyright (c) 2011 iMatix Corporation
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

#include "xrep.hpp"
#include "pipe.hpp"
#include "wire.hpp"
#include "random.hpp"
#include "likely.hpp"
#include "err.hpp"

zmq::xrep_t::xrep_t (class ctx_t *parent_, uint32_t tid_) :
    socket_base_t (parent_, tid_),
    prefetched (0),
    more_in (false),
    current_out (NULL),
    more_out (false),
    next_peer_id (generate_random ())
{
    options.type = ZMQ_XREP;

    //  TODO: Uncomment the following line when XREP will become true XREP
    //  rather than generic router socket.
    //  If peer disconnect there's noone to send reply to anyway. We can drop
    //  all the outstanding requests from that peer.
    //  options.delay_on_disconnect = false;

    options.send_identity = true;
    options.recv_identity = true;

    prefetched_msg.init ();
}

zmq::xrep_t::~xrep_t ()
{
    zmq_assert (outpipes.empty ());
    prefetched_msg.close ();
}

void zmq::xrep_t::xattach_pipe (pipe_t *pipe_)
{
    zmq_assert (pipe_);

    //  Generate a new unique peer identity.
    unsigned char buf [5];
    buf [0] = 0;
    put_uint32 (buf + 1, next_peer_id);
    blob_t identity (buf, 5);
    ++next_peer_id;

    //  Add the pipe to the map out outbound pipes.
    outpipe_t outpipe = {pipe_, true};
    bool ok = outpipes.insert (outpipes_t::value_type (
        identity, outpipe)).second;
    zmq_assert (ok);

    //  Add the pipe to the list of inbound pipes.
    pipe_->set_identity (identity);
    fq.attach (pipe_);    
}

void zmq::xrep_t::xterminated (pipe_t *pipe_)
{
    fq.terminated (pipe_);

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
    fq.activated (pipe_);
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
        if (msg_->flags () & msg_t::more) {

            more_out = true;

            //  Find the pipe associated with the identity stored in the prefix.
            //  If there's no such pipe just silently ignore the message.
            blob_t identity ((unsigned char*) msg_->data (), msg_->size ());
            outpipes_t::iterator it = outpipes.find (identity);

            if (it != outpipes.end ()) {
                current_out = it->second.pipe;
                msg_t empty;
                int rc = empty.init ();
                errno_assert (rc == 0);
                if (!current_out->check_write (&empty)) {
                    it->second.active = false;
                    more_out = false;
                    current_out = NULL;
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
    more_out = msg_->flags () & msg_t::more ? true : false;

    //  Push the message into the pipe. If there's no out pipe, just drop it.
    if (current_out) {
        bool ok = current_out->write (msg_);
        if (unlikely (!ok))
            current_out = NULL;
        else if (!more_out) {
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
    //  if there is a prefetched identity, return it.
    if (prefetched == 2)
    {
        int rc = msg_->init_size (prefetched_id.size ());
        errno_assert (rc == 0);
        memcpy (msg_->data (), prefetched_id.data (), prefetched_id.size ());
        msg_->set_flags (msg_t::more);
        prefetched = 1;
        return 0;
    }

    //  If there is a prefetched message, return it.
    if (prefetched == 1) {
        int rc = msg_->move (prefetched_msg);
        errno_assert (rc == 0);
        more_in = msg_->flags () & msg_t::more ? true : false;
        prefetched = 0;
        return 0;
    }

    pipe_t *pipe = NULL;
    while (true) {

        //  Get next message part.
        int rc = fq.recvpipe (msg_, flags_, &pipe);
        if (rc != 0)
            return -1;

        //  If identity is received, change the key assigned to the pipe.
        if (likely (!(msg_->flags () & msg_t::identity)))
            break;

        zmq_assert (!more_in);

        //  Empty identity means we can preserve the auto-generated identity.
        if (msg_->size () != 0) {

            //  Actual change of the identity.
            outpipes_t::iterator it = outpipes.begin ();
            while (it != outpipes.end ()) {
                if (it->second.pipe == pipe) {
                    blob_t identity ((unsigned char*) msg_->data (),
                        msg_->size ());
                    pipe->set_identity (identity);
                    outpipes.erase (it);
                    outpipe_t outpipe = {pipe, true};
                    outpipes.insert (outpipes_t::value_type (identity,
                        outpipe));
                    break;
                }
                ++it;
            }
            zmq_assert (it != outpipes.end ());
        }
    }

    //  If we are in the middle of reading a message, just return the next part.
    if (more_in) {
        more_in = msg_->flags () & msg_t::more ? true : false;
        return 0;
    }
 
    //  We are at the beginning of a new message. Move the message part we
    //  have to the prefetched and return the ID of the peer instead.
    int rc = prefetched_msg.move (*msg_);
    errno_assert (rc == 0);
    prefetched = 1;
    rc = msg_->close ();
    errno_assert (rc == 0);

    blob_t identity = pipe->get_identity ();
    rc = msg_->init_size (identity.size ());
    errno_assert (rc == 0);
    memcpy (msg_->data (), identity.data (), identity.size ());
    msg_->set_flags (msg_t::more);
    return 0;
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
    //  If we are in  the middle of reading the messages, there are
    //  definitely more parts available.
    if (more_in)
        return true;

    //  We may already have a message pre-fetched.
    if (prefetched > 0)
        return true;

    //  Try to read the next message to the pre-fetch buffer. If anything,
    //  it will be identity of the peer sending the message.
    msg_t id;
    id.init ();
    int rc = xrep_t::xrecv (&id, ZMQ_DONTWAIT);
    if (rc != 0 && errno == EAGAIN) {
        id.close ();
        return false;
    }
    zmq_assert (rc == 0);

    //  We have first part of the message prefetched now. We will store the
    //  prefetched identity as well.
    prefetched_id.assign ((unsigned char*) id.data (), id.size ());
    id.close ();
    prefetched = 2;

    return true;
}

bool zmq::xrep_t::xhas_out ()
{
    //  In theory, XREP socket is always ready for writing. Whether actual
    //  attempt to write succeeds depends on whitch pipe the message is going
    //  to be routed to.
    return true;
}

zmq::xrep_session_t::xrep_session_t (io_thread_t *io_thread_, bool connect_,
      socket_base_t *socket_, const options_t &options_,
      const char *protocol_, const char *address_) :
    session_base_t (io_thread_, connect_, socket_, options_, protocol_,
        address_)
{
}

zmq::xrep_session_t::~xrep_session_t ()
{
}

