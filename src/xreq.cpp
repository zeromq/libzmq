/*
    Copyright (c) 2009-2011 250bpm s.r.o.
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

#include "xreq.hpp"
#include "err.hpp"
#include "msg.hpp"

zmq::xreq_t::xreq_t (class ctx_t *parent_, uint32_t tid_) :
    socket_base_t (parent_, tid_),
    prefetched (false)
{
    options.type = ZMQ_XREQ;

    //  TODO: Uncomment the following line when XREQ will become true XREQ
    //  rather than generic dealer socket.
    //  If the socket is closing we can drop all the outbound requests. There'll
    //  be noone to receive the replies anyway.
    //  options.delay_on_close = false;

    options.send_identity = true;
    options.recv_identity = true;

    prefetched_msg.init ();
}

zmq::xreq_t::~xreq_t ()
{
    prefetched_msg.close ();
}

void zmq::xreq_t::xattach_pipe (pipe_t *pipe_)
{
    zmq_assert (pipe_);
    fq.attach (pipe_);
    lb.attach (pipe_);
}

int zmq::xreq_t::xsend (msg_t *msg_, int flags_)
{
    return lb.send (msg_, flags_);
}

int zmq::xreq_t::xrecv (msg_t *msg_, int flags_)
{
    //  If there is a prefetched message, return it.
    if (prefetched) {
        int rc = msg_->move (prefetched_msg);
        errno_assert (rc == 0);
        prefetched = false;
        return 0;
    }

    //  XREQ socket doesn't use identities. We can safely drop it and 
    while (true) {
        int rc = fq.recv (msg_, flags_);
        if (rc != 0)
            return rc;
        if (likely (!(msg_->flags () & msg_t::identity)))
            break;
    }
    return 0;
}

bool zmq::xreq_t::xhas_in ()
{
    //  We may already have a message pre-fetched.
    if (prefetched)
        return true;

    //  Try to read the next message to the pre-fetch buffer.
    int rc = xreq_t::xrecv (&prefetched_msg, ZMQ_DONTWAIT);
    if (rc != 0 && errno == EAGAIN)
        return false;
    zmq_assert (rc == 0);
    prefetched = true;
    return true;
}

bool zmq::xreq_t::xhas_out ()
{
    return lb.has_out ();
}

void zmq::xreq_t::xread_activated (pipe_t *pipe_)
{
    fq.activated (pipe_);
}

void zmq::xreq_t::xwrite_activated (pipe_t *pipe_)
{
    lb.activated (pipe_);
}

void zmq::xreq_t::xterminated (pipe_t *pipe_)
{
    fq.terminated (pipe_);
    lb.terminated (pipe_);
}

zmq::xreq_session_t::xreq_session_t (io_thread_t *io_thread_, bool connect_,
      socket_base_t *socket_, const options_t &options_,
      const char *protocol_, const char *address_) :
    session_base_t (io_thread_, connect_, socket_, options_, protocol_,
        address_)
{
}

zmq::xreq_session_t::~xreq_session_t ()
{
}

