/*
    Copyright (c) 2009-2011 250bpm s.r.o.
    Copyright (c) 2007-2009 iMatix Corporation
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

#include "pair.hpp"
#include "err.hpp"
#include "pipe.hpp"
#include "msg.hpp"

zmq::pair_t::pair_t (class ctx_t *parent_, uint32_t tid_) :
    socket_base_t (parent_, tid_),
    pipe (NULL)
{
    options.type = ZMQ_PAIR;
}

zmq::pair_t::~pair_t ()
{
    zmq_assert (!pipe);
}

void zmq::pair_t::xattach_pipe (pipe_t *pipe_)
{
    zmq_assert (!pipe);
    pipe = pipe_;
}

void zmq::pair_t::xterminated (pipe_t *pipe_)
{
    zmq_assert (pipe_ == pipe);
    pipe = NULL;
}

void zmq::pair_t::xread_activated (pipe_t *pipe_)
{
    //  There's just one pipe. No lists of active and inactive pipes.
    //  There's nothing to do here.
}

void zmq::pair_t::xwrite_activated (pipe_t *pipe_)
{
    //  There's just one pipe. No lists of active and inactive pipes.
    //  There's nothing to do here.
}

int zmq::pair_t::xsend (msg_t *msg_, int flags_)
{
    if (!pipe || !pipe->write (msg_)) {
        errno = EAGAIN;
        return -1;
    }

    if (!(flags_ & ZMQ_SNDMORE))
        pipe->flush ();

    //  Detach the original message from the data buffer.
    int rc = msg_->init ();
    errno_assert (rc == 0);

    return 0;
}

int zmq::pair_t::xrecv (msg_t *msg_, int flags_)
{
    //  Deallocate old content of the message.
    int rc = msg_->close ();
    errno_assert (rc == 0);

    if (!pipe || !pipe->read (msg_)) {

        //  Initialise the output parameter to be a 0-byte message.
        rc = msg_->init ();
        errno_assert (rc == 0);

        errno = EAGAIN;
        return -1;
    }
    return 0;
}

bool zmq::pair_t::xhas_in ()
{
    if (!pipe)
        return false;

    return pipe->check_read ();
}

bool zmq::pair_t::xhas_out ()
{
    if (!pipe)
        return false;

    msg_t msg;
    int rc = msg.init ();
    errno_assert (rc == 0);
    bool result = pipe->check_write (&msg);
    rc = msg.close ();
    errno_assert (rc == 0);
    return result;
}

zmq::pair_session_t::pair_session_t (io_thread_t *io_thread_, bool connect_,
      socket_base_t *socket_, const options_t &options_,
      const char *protocol_, const char *address_) :
    session_base_t (io_thread_, connect_, socket_, options_, protocol_,
         address_)
{
}

zmq::pair_session_t::~pair_session_t ()
{
}

