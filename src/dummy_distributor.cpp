/*
    Copyright (c) 2007-2009 FastMQ Inc.

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the Lesser GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    Lesser GNU General Public License for more details.

    You should have received a copy of the Lesser GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "../include/zmq.h"

#include "dummy_distributor.hpp"
#include "pipe_writer.hpp"
#include "err.hpp"
#include "session.hpp"
#include "msg.hpp"

zmq::dummy_distributor_t::dummy_distributor_t () :
    session (NULL)
{
}

void zmq::dummy_distributor_t::set_session (session_t *session_)
{
    zmq_assert (!session);
    session = session_;
}

void zmq::dummy_distributor_t::shutdown ()
{
    //  No need to deallocate pipe here. It'll be deallocated during the
    //  shutdown of the dispatcher.
    delete this;
}

void zmq::dummy_distributor_t::terminate ()
{
   if (pipe)
       pipe->terminate ();

   delete this;
}

zmq::dummy_distributor_t::~dummy_distributor_t ()
{
}

void zmq::dummy_distributor_t::attach_pipe (pipe_writer_t *pipe_)
{
    zmq_assert (!pipe);
    pipe = pipe_;
}

void zmq::dummy_distributor_t::detach_pipe (pipe_writer_t *pipe_)
{
    zmq_assert (pipe == pipe_);
    pipe = NULL;
}

bool zmq::dummy_distributor_t::empty ()
{
    return pipe == NULL;
}

bool zmq::dummy_distributor_t::send (zmq_msg *msg_)
{
    return pipe && pipe->write (msg_);
}

void zmq::dummy_distributor_t::flush ()
{
    if (pipe)
        pipe->flush ();
}

