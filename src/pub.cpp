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

#include "pub.hpp"
#include "msg.hpp"

zmq::pub_t::pub_t (class ctx_t *parent_, uint32_t tid_) :
    xpub_t (parent_, tid_)
{
    options.type = ZMQ_PUB;
}

zmq::pub_t::~pub_t ()
{
}

int zmq::pub_t::xrecv (class msg_t *msg_, int flags_)
{
    //  Messages cannot be received from PUB socket.
    errno = ENOTSUP;
    return -1;
}

bool zmq::pub_t::xhas_in ()
{
    return false;
}

zmq::pub_session_t::pub_session_t (io_thread_t *io_thread_, bool connect_,
      socket_base_t *socket_, const options_t &options_,
      const char *protocol_, const char *address_) :
    xpub_session_t (io_thread_, connect_, socket_, options_, protocol_,
        address_)
{
}

zmq::pub_session_t::~pub_session_t ()
{
}

