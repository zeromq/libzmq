/*
    Copyright (c) 2007-2014 Contributors as noted in the AUTHORS file

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
    message_begins (true),
    reply_pipe (NULL),
    request_id_frames_enabled (false),
    request_id (generate_random()),
    strict (true)
{
    options.type = ZMQ_REQ;
}

zmq::req_t::~req_t ()
{
}

int zmq::req_t::xsend (msg_t *msg_)
{
    //  If we've sent a request and we still haven't got the reply,
    //  we can't send another request unless the strict option is disabled.
    if (receiving_reply) {
        if (strict) {
            errno = EFSM;
            return -1;
        }

        if (reply_pipe)
            reply_pipe->terminate (false);
        receiving_reply = false;
        message_begins = true;
    }

    //  First part of the request is the request identity.
    if (message_begins) {
        reply_pipe = NULL;

        if (request_id_frames_enabled) {
            request_id++;

            msg_t id;
            int rc = id.init_data (&request_id, sizeof (request_id), NULL, NULL);
            errno_assert (rc == 0);
            id.set_flags (msg_t::more);

            rc = dealer_t::sendpipe (&id, &reply_pipe);
            if (rc != 0)
                return -1;
        }

        msg_t bottom;
        int rc = bottom.init ();
        errno_assert (rc == 0);
        bottom.set_flags (msg_t::more);

        rc = dealer_t::sendpipe (&bottom, &reply_pipe);
        if (rc != 0)
            return -1;
        zmq_assert (reply_pipe);

        message_begins = false;

        // Eat all currently avaliable messages before the request is fully
        // sent. This is done to avoid:
        //   REQ sends request to A, A replies, B replies too.
        //   A's reply was first and matches, that is used.
        //   An hour later REQ sends a request to B. B's old reply is used.
        msg_t drop;
        while (true) {
            rc = drop.init ();
            errno_assert (rc == 0);
            rc = dealer_t::xrecv (&drop);
            if (rc != 0)
                break;
            drop.close ();
        }
    }

    bool more = msg_->flags () & msg_t::more ? true : false;

    int rc = dealer_t::xsend (msg_);
    if (rc != 0)
        return rc;

    //  If the request was fully sent, flip the FSM into reply-receiving state.
    if (!more) {
        receiving_reply = true;
        message_begins = true;
    }

    return 0;
}

int zmq::req_t::xrecv (msg_t *msg_)
{
    //  If request wasn't send, we can't wait for reply.
    if (!receiving_reply) {
        errno = EFSM;
        return -1;
    }

    //  Skip messages until one with the right first frames is found.
    while (message_begins) {
        //  If enabled, the first frame must have the correct request_id.
        if (request_id_frames_enabled) {
            int rc = recv_reply_pipe (msg_);
            if (rc != 0)
                return rc;

            if (unlikely (!(msg_->flags () & msg_t::more) ||
                          msg_->size () != sizeof (request_id) ||
                          *static_cast<uint32_t *> (msg_->data ()) != request_id)) {
                //  Skip the remaining frames and try the next message
                while (msg_->flags () & msg_t::more) {
                    rc = recv_reply_pipe (msg_);
                    errno_assert (rc == 0);
                }
                continue;
            }
        }

        //  The next frame must be 0.
        // TODO: Failing this check should also close the connection with the peer!
        int rc = recv_reply_pipe (msg_);
        if (rc != 0)
            return rc;

        if (unlikely (!(msg_->flags () & msg_t::more) || msg_->size () != 0)) {
            //  Skip the remaining frames and try the next message
            while (msg_->flags () & msg_t::more) {
                rc = recv_reply_pipe (msg_);
                errno_assert (rc == 0);
            }
            continue;
        }

        message_begins = false;
    }

    int rc = recv_reply_pipe (msg_);
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

int zmq::req_t::xsetsockopt (int option_, const void *optval_, size_t optvallen_)
{
    bool is_int = (optvallen_ == sizeof (int));
    int value = is_int? *((int *) optval_): 0;
    switch (option_) {
        case ZMQ_REQ_CORRELATE:
            if (is_int && value >= 0) {
                request_id_frames_enabled = (value != 0);
                return 0;
            }
            break;

        case ZMQ_REQ_RELAXED:
            if (is_int && value >= 0) {
                strict = (value == 0);
                return 0;
            }
            break;

        default:
            break;
    }

    return dealer_t::xsetsockopt (option_, optval_, optvallen_);
}

void zmq::req_t::xpipe_terminated (pipe_t *pipe_)
{
    if (reply_pipe == pipe_)
        reply_pipe = NULL;
    dealer_t::xpipe_terminated (pipe_);
}

int zmq::req_t::recv_reply_pipe (msg_t *msg_)
{
    while (true) {
        pipe_t *pipe = NULL;
        int rc = dealer_t::recvpipe (msg_, &pipe);
        if (rc != 0)
            return rc;
        if (!reply_pipe || pipe == reply_pipe)
            return 0;
    }
}

zmq::req_session_t::req_session_t (io_thread_t *io_thread_, bool connect_,
      socket_base_t *socket_, const options_t &options_,
      address_t *addr_) :
    session_base_t (io_thread_, connect_, socket_, options_, addr_),
    state (bottom)
{
}

zmq::req_session_t::~req_session_t ()
{
}

int zmq::req_session_t::push_msg (msg_t *msg_)
{
    switch (state) {
    case bottom:
        if (msg_->flags () == msg_t::more && msg_->size () == 0) {
            state = body;
            return session_base_t::push_msg (msg_);
        }
        break;
    case body:
        if (msg_->flags () == msg_t::more)
            return session_base_t::push_msg (msg_);
        if (msg_->flags () == 0) {
            state = bottom;
            return session_base_t::push_msg (msg_);
        }
        break;
    }
    errno = EFAULT;
    return -1;
}

void zmq::req_session_t::reset ()
{
    session_base_t::reset ();
    state = bottom;
}
