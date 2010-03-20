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

#include "xrep.hpp"
#include "err.hpp"
#include "pipe.hpp"

zmq::xrep_t::xrep_t (class app_thread_t *parent_) :
    socket_base_t (parent_)
{
    options.requires_in = true;
    options.requires_out = true;

    //  On connect, pipes are created only after initial handshaking.
    //  That way we are aware of the peer's identity when binding to the pipes.
    options.immediate_connect = false;

    //  XREP is unfunctional at the moment. Crash here!
    zmq_assert (false);
}

zmq::xrep_t::~xrep_t ()
{
}

void zmq::xrep_t::xattach_pipes (class reader_t *inpipe_,
    class writer_t *outpipe_, const blob_t &peer_identity_)
{
    zmq_assert (inpipe_ && outpipe_);
    fq.attach (inpipe_);

    //  TODO: What if new connection has same peer identity as the old one?
    bool ok = outpipes.insert (std::make_pair (
        peer_identity_, outpipe_)).second;
    zmq_assert (ok);
}

void zmq::xrep_t::xdetach_inpipe (class reader_t *pipe_)
{
    zmq_assert (pipe_);
    fq.detach (pipe_);
}

void zmq::xrep_t::xdetach_outpipe (class writer_t *pipe_)
{
    for (outpipes_t::iterator it = outpipes.begin ();
          it != outpipes.end (); ++it)
        if (it->second == pipe_) {
            outpipes.erase (it);
            return;
        }
    zmq_assert (false);
}

void zmq::xrep_t::xkill (class reader_t *pipe_)
{
    fq.kill (pipe_);
}

void zmq::xrep_t::xrevive (class reader_t *pipe_)
{
    fq.revive (pipe_);
}

void zmq::xrep_t::xrevive (class writer_t *pipe_)
{
}

int zmq::xrep_t::xsetsockopt (int option_, const void *optval_,
    size_t optvallen_)
{
    errno = EINVAL;
    return -1;
}

int zmq::xrep_t::xsend (zmq_msg_t *msg_, int flags_)
{
    unsigned char *data = (unsigned char*) zmq_msg_data (msg_);
    size_t size = zmq_msg_size (msg_);

    //  Check whether the message is well-formed.
    zmq_assert (size >= 1);
    zmq_assert (size_t (*data + 1) <= size);

    //  Find the corresponding outbound pipe. If there's none, just drop the
    //  message.
    //  TODO: There's an allocation here! It's the critical path! Get rid of it!
    blob_t identity (data + 1, *data);
    outpipes_t::iterator it = outpipes.find (identity);
    if (it == outpipes.end ()) {
        int rc = zmq_msg_close (msg_);
        zmq_assert (rc == 0);
        rc = zmq_msg_init (msg_);
        zmq_assert (rc == 0);
        return 0;
    }

    //  Push message to the selected pipe.
    if (!it->second->write (msg_)) {
        errno = EAGAIN;
        return -1;
    }

    it->second->flush ();

    //  Detach the message from the data buffer.
    int rc = zmq_msg_init (msg_);
    zmq_assert (rc == 0);

    return 0;
}

int zmq::xrep_t::xrecv (zmq_msg_t *msg_, int flags_)
{
    return fq.recv (msg_, flags_);
}

bool zmq::xrep_t::xhas_in ()
{
    return fq.has_in ();
}

bool zmq::xrep_t::xhas_out ()
{
    //  In theory, XREP socket is always ready for writing. Whether actual
    //  attempt to write succeeds depends on whitch pipe the message is going
    //  to be routed to.
    return true;
}


