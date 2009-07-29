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

#include "../include/zs.h"

#include "dummy_aggregator.hpp"
#include "err.hpp"
#include "pipe_reader.hpp"
#include "session.hpp"

//  Swaps pipes at specified indices. 
#define swap_pipes(i1_, i2_) \
    std::swap (pipes [i1_], pipes [i2_]);\
    pipes [i1_]->set_index (i1_);\
    pipes [i2_]->set_index (i2_);

zs::dummy_aggregator_t::dummy_aggregator_t () :
    session (NULL),
    pipe (NULL),
    active (false)
{
}

void zs::dummy_aggregator_t::set_session (session_t *session_)
{
    zs_assert (!session);
    session = session_;
}

void zs::dummy_aggregator_t::shutdown ()
{
    //  No need to deallocate the pipe here. It'll be deallocated during the
    //  shutdown of the dispatcher.
    delete this;
}

void zs::dummy_aggregator_t::terminate ()
{
    if (pipe)
        pipe->terminate ();

   delete this;
}

zs::dummy_aggregator_t::~dummy_aggregator_t ()
{
}

void zs::dummy_aggregator_t::attach_pipe (pipe_reader_t *pipe_)
{
    zs_assert (!pipe);
    pipe = pipe_;
    active = true;

    //  Associate new pipe with the mux object.
    pipe_->set_mux (this);
    session->revive ();
}

void zs::dummy_aggregator_t::detach_pipe (pipe_reader_t *pipe_)
{
    zs_assert (pipe == pipe_);
    deactivate (pipe_);
    pipe = NULL;
}

bool zs::dummy_aggregator_t::empty ()
{
    return pipe == NULL;
}

bool zs::dummy_aggregator_t::recv (zs_msg *msg_)
{
    //  Deallocate old content of the message.
    zs_msg_close (msg_);
        
    //  Try to read from the pipe.
    if (pipe && pipe->read (msg_))
        return true;

    //  No message is available. Initialise the output parameter
    //  to be a 0-byte message.
    zs_msg_init (msg_);
    return false;
}

void zs::dummy_aggregator_t::deactivate (pipe_reader_t *pipe_)
{
    active = false;
}

void zs::dummy_aggregator_t::reactivate (pipe_reader_t *pipe_)
{
    active = true;
}
