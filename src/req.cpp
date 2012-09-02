/*
    Copyright (c) 2009-2011 250bpm s.r.o.
    Copyright (c) 2007-2009 iMatix Corporation
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

#include "req.hpp"
#include "err.hpp"
#include "msg.hpp"
#include "wire.hpp"
#include "random.hpp"
#include "likely.hpp"

zmq::req_t::req_t (class ctx_t *parent_, uint32_t tid_, int sid_) :
    dealer_t (parent_, tid_, sid_),
    receiving_reply (false),
    message_begins (true)
{
    options.type = ZMQ_REQ;
}

zmq::req_t::~req_t ()
{
}

int zmq::req_t::xsend (msg_t *msg_, int flags_)
{
    //  If we've sent a request and we still haven't got the reply,
    //  we can't send another request.
    if (receiving_reply) {
        errno = EFSM;
        return -1;
    }

    //  First part of the request is the request identity.
    if (message_begins) {
        msg_t bottom;
        int rc = bottom.init ();
        errno_assert (rc == 0);
        bottom.set_flags (msg_t::more);
        rc = dealer_t::xsend (&bottom, 0);
        if (rc != 0)
            return -1;
        message_begins = false;
    }

    bool more = msg_->flags () & msg_t::more ? true : false;

    int rc = dealer_t::xsend (msg_, flags_);
    if (rc != 0)
        return rc;

    //  If the request was fully sent, flip the FSM into reply-receiving state.
    if (!more) {
        receiving_reply = true;
        message_begins = true;
    }

    return 0;
}

int zmq::req_t::xrecv (msg_t *msg_, int flags_)
{
    //  If request wasn't send, we can't wait for reply.
    if (!receiving_reply) {
        errno = EFSM;
        return -1;
    }

    //  First part of the reply should be the original request ID.
    if (message_begins) {
        int rc = dealer_t::xrecv (msg_, flags_);
        if (rc != 0)
            return rc;

        // TODO: This should also close the connection with the peer!
        if (unlikely (!(msg_->flags () & msg_t::more) || msg_->size () != 0)) {
            while (true) {
                int rc = dealer_t::xrecv (msg_, flags_);
                errno_assert (rc == 0);
                if (!(msg_->flags () & msg_t::more))
                    break;
            }
            msg_->close ();
            msg_->init ();
            errno = EAGAIN;
            return -1;
        }

        message_begins = false;
    }

    int rc = dealer_t::xrecv (msg_, flags_);
    if (rc != 0)
        return rc;

    //  If the reply is fully received, flip the FSM into request-sending state.
    if (!(msg_->flags () & msg_t::more)) {
        receiving_reply = false;
        message_begins = true;
    }

    return 0;
}

bool zmq::req_t::xhas_in ()
{
    //  TODO: Duplicates should be removed here.

    if (!receiving_reply)
        return false;

    return dealer_t::xhas_in ();
}

bool zmq::req_t::xhas_out ()
{
    if (receiving_reply)
        return false;

    return dealer_t::xhas_out ();
}

zmq::req_session_t::req_session_t (io_thread_t *io_thread_, bool connect_,
      socket_base_t *socket_, const options_t &options_,
      const address_t *addr_) :
    dealer_session_t (io_thread_, connect_, socket_, options_, addr_),
    state (identity)
{
}

zmq::req_session_t::~req_session_t ()
{
    state = options.recv_identity ? identity : bottom;
}

int zmq::req_session_t::push_msg (msg_t *msg_)
{
    switch (state) {
    case bottom:
        if (msg_->flags () == msg_t::more && msg_->size () == 0) {
            state = body;
            return dealer_session_t::push_msg (msg_);
        }
        break;
    case body:
        if (msg_->flags () == msg_t::more)
            return dealer_session_t::push_msg (msg_);
        if (msg_->flags () == 0) {
            state = bottom;
            return dealer_session_t::push_msg (msg_);
        }
        break;
    case identity:
        if (msg_->flags () == 0) {
            state = bottom;
            return dealer_session_t::push_msg (msg_);
        }
        break;
    }
    errno = EFAULT;
    return -1;
}

void zmq::req_session_t::reset ()
{
    session_base_t::reset ();
    state = identity;
}
