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

#include "req.hpp"
#include "err.hpp"
#include "msg.hpp"
#include "wire.hpp"
#include "random.hpp"
#include "likely.hpp"

zmq::req_t::req_t (class ctx_t *parent_, uint32_t tid_) :
    xreq_t (parent_, tid_),
    receiving_reply (false),
    message_begins (true),
    request_id (generate_random ())
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
        msg_t prefix;
        int rc = prefix.init_size (4);
        errno_assert (rc == 0);
        prefix.set_flags (msg_t::label);
        unsigned char *data = (unsigned char*) prefix.data ();
        put_uint32 (data, request_id);
        rc = xreq_t::xsend (&prefix, flags_);
        if (rc != 0)
            return rc;
        message_begins = false;
    }

    bool more = msg_->flags () & (msg_t::more | msg_t::label) ? true : false;

    int rc = xreq_t::xsend (msg_, flags_);
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
        int rc = xreq_t::xrecv (msg_, flags_);
        if (rc != 0)
            return rc;

        // TODO: This should also close the connection with the peer!
        if (unlikely (!(msg_->flags () & msg_t::label) || msg_->size () != 4)) {
            while (true) {
                int rc = xreq_t::xrecv (msg_, flags_);
                errno_assert (rc == 0);
                if (!(msg_->flags () & (msg_t::label | msg_t::more)))
                    break;
            }
            msg_->close ();
            msg_->init ();
            errno = EAGAIN;
            return -1;
        }
        
        unsigned char *data = (unsigned char*) msg_->data ();
        if (unlikely (get_uint32 (data) != request_id)) {
            while (true) {
                int rc = xreq_t::xrecv (msg_, flags_);
                errno_assert (rc == 0);
                if (!(msg_->flags () & (msg_t::label | msg_t::more)))
                    break;
            }
            msg_->close ();
            msg_->init ();
            errno = EAGAIN;
            return -1;
        }
        message_begins = false;
    }

    int rc = xreq_t::xrecv (msg_, flags_);
    if (rc != 0)
        return rc;

    //  If the reply is fully received, flip the FSM into request-sending state.
    if (!(msg_->flags () & (msg_t::more | msg_t::label))) {
        request_id++;
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

    return xreq_t::xhas_in ();
}

bool zmq::req_t::xhas_out ()
{
    if (receiving_reply)
        return false;

    return xreq_t::xhas_out ();
}

zmq::req_session_t::req_session_t (io_thread_t *io_thread_, bool connect_,
      socket_base_t *socket_, const options_t &options_,
      const char *protocol_, const char *address_) :
    xreq_session_t (io_thread_, connect_, socket_, options_, protocol_,
        address_)
{
}

zmq::req_session_t::~req_session_t ()
{
}

int zmq::req_session_t::write (msg_t *msg_)
{
    if (state == request_id) {
        if (msg_->flags () == msg_t::label && msg_->size () == 4) {
            state = body;
            return xreq_session_t::write (msg_);
        }
    }
    else {
        if (msg_->flags () == msg_t::more)
            return xreq_session_t::write (msg_);
        if (msg_->flags () == 0) {
            state = request_id;
            return xreq_session_t::write (msg_);
        }
    }
    errno = EFAULT;
    return -1;
}

