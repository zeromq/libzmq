/*
    Copyright (c) 2009-2011 250bpm s.r.o.
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

#include "rep.hpp"
#include "err.hpp"
#include "msg.hpp"

zmq::rep_t::rep_t (class ctx_t *parent_, uint32_t tid_) :
    xrep_t (parent_, tid_),
    sending_reply (false),
    request_begins (true)
{
    options.type = ZMQ_REP;
}

zmq::rep_t::~rep_t ()
{
}

int zmq::rep_t::xsend (msg_t *msg_, int flags_)
{
    //  If we are in the middle of receiving a request, we cannot send reply.
    if (!sending_reply) {
        errno = EFSM;
        return -1;
    }

    bool more = msg_->flags () & msg_t::more ? true : false;

    //  Push message to the reply pipe.
    int rc = xrep_t::xsend (msg_, flags_);
    if (rc != 0)
        return rc;

    //  If the reply is complete flip the FSM back to request receiving state.
    if (!more)
        sending_reply = false;

    return 0;
}

int zmq::rep_t::xrecv (msg_t *msg_, int flags_)
{
    //  If we are in middle of sending a reply, we cannot receive next request.
    if (sending_reply) {
        errno = EFSM;
        return -1;
    }

    //  First thing to do when receiving a request is to copy all the labels
    //  to the reply pipe.
    if (request_begins) {
        while (true) {
            int rc = xrep_t::xrecv (msg_, flags_);
            if (rc != 0)
                return rc;
            zmq_assert (msg_->flags () & msg_t::more);
            bool bottom = (msg_->size () == 0);
            rc = xrep_t::xsend (msg_, flags_);
            errno_assert (rc == 0);
            if (bottom)
                break;
        }
        request_begins = false;
    }

    //  Get next message part to return to the user.
    int rc = xrep_t::xrecv (msg_, flags_);
    if (rc != 0)
       return rc;

    //  If whole request is read, flip the FSM to reply-sending state.
    if (!(msg_->flags () & msg_t::more)) {
        sending_reply = true;
        request_begins = true;
    }

    return 0;
}

bool zmq::rep_t::xhas_in ()
{
    if (sending_reply)
        return false;

    return xrep_t::xhas_in ();
}

bool zmq::rep_t::xhas_out ()
{
    if (!sending_reply)
        return false;

    return xrep_t::xhas_out ();
}

zmq::rep_session_t::rep_session_t (io_thread_t *io_thread_, bool connect_,
      socket_base_t *socket_, const options_t &options_,
      const char *protocol_, const char *address_) :
    xrep_session_t (io_thread_, connect_, socket_, options_, protocol_,
        address_)
{
}

zmq::rep_session_t::~rep_session_t ()
{
}

