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

#include "dealer.hpp"
#include "err.hpp"
#include "msg.hpp"

zmq::dealer_t::dealer_t (class ctx_t *parent_, uint32_t tid_, int sid_) :
    socket_base_t (parent_, tid_, sid_)
{
    options.type = ZMQ_DEALER;

    //  TODO: Uncomment the following line when DEALER will become true DEALER
    //  rather than generic dealer socket.
    //  If the socket is closing we can drop all the outbound requests. There'll
    //  be noone to receive the replies anyway.
    //  options.delay_on_close = false;
}

zmq::dealer_t::~dealer_t ()
{
}

void zmq::dealer_t::xattach_pipe (pipe_t *pipe_, bool icanhasall_)
{
    // icanhasall_ is unused
    (void) icanhasall_;

    zmq_assert (pipe_);
    fq.attach (pipe_);
    lb.attach (pipe_);
}

int zmq::dealer_t::xsend (msg_t *msg_)
{
    return lb.send (msg_);
}

int zmq::dealer_t::xrecv (msg_t *msg_)
{
    return fq.recv (msg_);
}

bool zmq::dealer_t::xhas_in ()
{
    return fq.has_in ();
}

bool zmq::dealer_t::xhas_out ()
{
    return lb.has_out ();
}

void zmq::dealer_t::xread_activated (pipe_t *pipe_)
{
    fq.activated (pipe_);
}

void zmq::dealer_t::xwrite_activated (pipe_t *pipe_)
{
    lb.activated (pipe_);
}

void zmq::dealer_t::xterminated (pipe_t *pipe_)
{
    fq.terminated (pipe_);
    lb.terminated (pipe_);
}

zmq::dealer_session_t::dealer_session_t (io_thread_t *io_thread_, bool connect_,
      socket_base_t *socket_, const options_t &options_,
      const address_t *addr_) :
    session_base_t (io_thread_, connect_, socket_, options_, addr_)
{
}

zmq::dealer_session_t::~dealer_session_t ()
{
}

