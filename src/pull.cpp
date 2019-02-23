/*
    Copyright (c) 2007-2016 Contributors as noted in the AUTHORS file

    This file is part of libzmq, the ZeroMQ core engine in C++.

    libzmq is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License (LGPL) as published
    by the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    As a special exception, the Contributors give you permission to link
    this library with independent modules to produce an executable,
    regardless of the license terms of these independent modules, and to
    copy and distribute the resulting executable under terms of your choice,
    provided that you also meet, for each linked independent module, the
    terms and conditions of the license of that module. An independent
    module is a module which is not derived from or based on this library.
    If you modify this library, you must extend this exception to your
    version of the library.

    libzmq is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
    FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
    License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "precompiled.hpp"
#include "macros.hpp"
#include "pull.hpp"
#include "err.hpp"
#include "msg.hpp"
#include "pipe.hpp"

zmq::pull_t::pull_t (class ctx_t *parent_, uint32_t tid_, int sid_) :
    socket_base_t (parent_, tid_, sid_)
{
    options.type = ZMQ_PULL;
}

zmq::pull_t::~pull_t ()
{
}

void zmq::pull_t::xattach_pipe (pipe_t *pipe_,
                                bool subscribe_to_all_,
                                bool locally_initiated_)
{
    LIBZMQ_UNUSED (subscribe_to_all_);
    LIBZMQ_UNUSED (locally_initiated_);

    zmq_assert (pipe_);
    _fq.attach (pipe_);
}

void zmq::pull_t::xread_activated (pipe_t *pipe_)
{
    _fq.activated (pipe_);
}

void zmq::pull_t::xpipe_terminated (pipe_t *pipe_)
{
    _fq.pipe_terminated (pipe_);
}

int zmq::pull_t::xrecv (msg_t *msg_)
{
    return _fq.recv (msg_);
}

bool zmq::pull_t::xhas_in ()
{
    return _fq.has_in ();
}
