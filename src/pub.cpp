/*
    Copyright (c) 2007-2013 Contributors as noted in the AUTHORS file

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
#include "pipe.hpp"
#include "err.hpp"
#include "msg.hpp"

zmq::pub_t::pub_t (class ctx_t *parent_, uint32_t tid_, int sid_) :
    xpub_t (parent_, tid_, sid_)
{
    options.type = ZMQ_PUB;
}

zmq::pub_t::~pub_t ()
{
}

void zmq::pub_t::xattach_pipe (pipe_t *pipe_, bool subscribe_to_all_)
{
    zmq_assert (pipe_);

    //  Don't delay pipe termination as there is no one
    //  to receive the delimiter.
    pipe_->set_nodelay ();

    xpub_t::xattach_pipe (pipe_, subscribe_to_all_);
}

int zmq::pub_t::xrecv (class msg_t *)
{
    //  Messages cannot be received from PUB socket.
    errno = ENOTSUP;
    return -1;
}

bool zmq::pub_t::xhas_in ()
{
    return false;
}
