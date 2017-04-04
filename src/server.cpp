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
#include "server.hpp"
#include "pipe.hpp"
#include "wire.hpp"
#include "random.hpp"
#include "likely.hpp"
#include "err.hpp"

zmq::server_t::server_t (class ctx_t *parent_, uint32_t tid_, int sid_) :
    socket_base_t (parent_, tid_, sid_, true),
    next_rid (generate_random ())
{
    options.type = ZMQ_SERVER;
}

zmq::server_t::~server_t ()
{
    zmq_assert (outpipes.empty ());
}

void zmq::server_t::xattach_pipe (pipe_t *pipe_, bool subscribe_to_all_)
{
    LIBZMQ_UNUSED (subscribe_to_all_);

    zmq_assert (pipe_);

    uint32_t routing_id = next_rid++;
    if (!routing_id)
        routing_id = next_rid++;        //  Never use RID zero

    pipe_->set_routing_id (routing_id);
    //  Add the record into output pipes lookup table
    outpipe_t outpipe = {pipe_, true};
    bool ok = outpipes.insert (outpipes_t::value_type (routing_id, outpipe)).second;
    zmq_assert (ok);

    fq.attach (pipe_);
}

void zmq::server_t::xpipe_terminated (pipe_t *pipe_)
{
    outpipes_t::iterator it = outpipes.find (pipe_->get_routing_id ());
    zmq_assert (it != outpipes.end ());
    outpipes.erase (it);
    fq.pipe_terminated (pipe_);
}

void zmq::server_t::xread_activated (pipe_t *pipe_)
{
    fq.activated (pipe_);
}

void zmq::server_t::xwrite_activated (pipe_t *pipe_)
{
    outpipes_t::iterator it;
    for (it = outpipes.begin (); it != outpipes.end (); ++it)
        if (it->second.pipe == pipe_)
            break;

    zmq_assert (it != outpipes.end ());
    zmq_assert (!it->second.active);
    it->second.active = true;
}

int zmq::server_t::xsend (msg_t *msg_)
{
    //  SERVER sockets do not allow multipart data (ZMQ_SNDMORE)
    if (msg_->flags () & msg_t::more) {
        errno = EINVAL;
        return -1;
    }
    //  Find the pipe associated with the routing stored in the message.
    uint32_t routing_id = msg_->get_routing_id ();
    outpipes_t::iterator it = outpipes.find (routing_id);

    if (it != outpipes.end ()) {
        if (!it->second.pipe->check_write ()) {
            it->second.active = false;
            errno = EAGAIN;
            return -1;
        }
    }
    else {
        errno = EHOSTUNREACH;
        return -1;
    }

    //  Message might be delivered over inproc, so we reset routing id
    int rc = msg_->reset_routing_id ();
    errno_assert (rc == 0);

    bool ok = it->second.pipe->write (msg_);
    if (unlikely (!ok)) {
        // Message failed to send - we must close it ourselves.
        rc = msg_->close ();
        errno_assert (rc == 0);
    }
    else
        it->second.pipe->flush ();

    //  Detach the message from the data buffer.
    rc = msg_->init ();
    errno_assert (rc == 0);

    return 0;
}

int zmq::server_t::xrecv (msg_t *msg_)
{
    pipe_t *pipe = NULL;
    int rc = fq.recvpipe (msg_, &pipe);

    // Drop any messages with more flag
    while (rc == 0 && msg_->flags () & msg_t::more) {

        // drop all frames of the current multi-frame message
        rc = fq.recvpipe (msg_, NULL);

        while (rc == 0 && msg_->flags () & msg_t::more)
            rc = fq.recvpipe (msg_, NULL);

        // get the new message
        if (rc == 0)
            rc = fq.recvpipe (msg_, &pipe);
    }

    if (rc != 0)
        return rc;

    zmq_assert (pipe != NULL);

    uint32_t routing_id = pipe->get_routing_id ();
    msg_->set_routing_id (routing_id);

    return 0;
}

bool zmq::server_t::xhas_in ()
{
    return fq.has_in ();
}

bool zmq::server_t::xhas_out ()
{
    //  In theory, SERVER socket is always ready for writing. Whether actual
    //  attempt to write succeeds depends on which pipe the message is going
    //  to be routed to.
    return true;
}

zmq::blob_t zmq::server_t::get_credential () const
{
    return fq.get_credential ();
}
