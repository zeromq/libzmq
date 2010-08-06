/*
    Copyright (c) 2007-2010 iMatix Corporation

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

#include "xreq.hpp"
#include "err.hpp"

zmq::xreq_t::xreq_t (class ctx_t *parent_, uint32_t slot_) :
    socket_base_t (parent_, slot_)
{
    options.requires_in = true;
    options.requires_out = true;
}

zmq::xreq_t::~xreq_t ()
{
}

void zmq::xreq_t::xattach_pipes (class reader_t *inpipe_,
    class writer_t *outpipe_, const blob_t &peer_identity_)
{
    zmq_assert (inpipe_ && outpipe_);
    fq.attach (inpipe_);
    lb.attach (outpipe_);
}

void zmq::xreq_t::xterm_pipes ()
{
    fq.term_pipes ();
    lb.term_pipes ();
}

bool zmq::xreq_t::xhas_pipes ()
{
    return fq.has_pipes () || lb.has_pipes ();
}

int zmq::xreq_t::xsend (zmq_msg_t *msg_, int flags_)
{
    return lb.send (msg_, flags_);
}

int zmq::xreq_t::xrecv (zmq_msg_t *msg_, int flags_)
{
    return fq.recv (msg_, flags_);
}

bool zmq::xreq_t::xhas_in ()
{
    return fq.has_in ();
}

bool zmq::xreq_t::xhas_out ()
{
    return lb.has_out ();
}

