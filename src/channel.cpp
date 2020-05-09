/*
    Copyright (c) 2007-2020 Contributors as noted in the AUTHORS file

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
#include "channel.hpp"
#include "err.hpp"
#include "pipe.hpp"
#include "msg.hpp"

zmq::channel_t::channel_t (class ctx_t *parent_, uint32_t tid_, int sid_) :
    socket_base_t (parent_, tid_, sid_, true),
    _pipe (NULL)
{
    options.type = ZMQ_CHANNEL;
}

zmq::channel_t::~channel_t ()
{
    zmq_assert (!_pipe);
}

void zmq::channel_t::xattach_pipe (pipe_t *pipe_,
                                   bool subscribe_to_all_,
                                   bool locally_initiated_)
{
    LIBZMQ_UNUSED (subscribe_to_all_);
    LIBZMQ_UNUSED (locally_initiated_);

    zmq_assert (pipe_ != NULL);

    //  ZMQ_PAIR socket can only be connected to a single peer.
    //  The socket rejects any further connection requests.
    if (_pipe == NULL)
        _pipe = pipe_;
    else
        pipe_->terminate (false);
}

void zmq::channel_t::xpipe_terminated (pipe_t *pipe_)
{
    if (pipe_ == _pipe)
        _pipe = NULL;
}

void zmq::channel_t::xread_activated (pipe_t *)
{
    //  There's just one pipe. No lists of active and inactive pipes.
    //  There's nothing to do here.
}

void zmq::channel_t::xwrite_activated (pipe_t *)
{
    //  There's just one pipe. No lists of active and inactive pipes.
    //  There's nothing to do here.
}

int zmq::channel_t::xsend (msg_t *msg_)
{
    //  CHANNEL sockets do not allow multipart data (ZMQ_SNDMORE)
    if (msg_->flags () & msg_t::more) {
        errno = EINVAL;
        return -1;
    }

    if (!_pipe || !_pipe->write (msg_)) {
        errno = EAGAIN;
        return -1;
    }

    _pipe->flush ();

    //  Detach the original message from the data buffer.
    const int rc = msg_->init ();
    errno_assert (rc == 0);

    return 0;
}

int zmq::channel_t::xrecv (msg_t *msg_)
{
    //  Deallocate old content of the message.
    int rc = msg_->close ();
    errno_assert (rc == 0);

    if (!_pipe) {
        //  Initialise the output parameter to be a 0-byte message.
        rc = msg_->init ();
        errno_assert (rc == 0);

        errno = EAGAIN;
        return -1;
    }

    // Drop any messages with more flag
    bool read = _pipe->read (msg_);
    while (read && msg_->flags () & msg_t::more) {
        // drop all frames of the current multi-frame message
        read = _pipe->read (msg_);
        while (read && msg_->flags () & msg_t::more)
            read = _pipe->read (msg_);

        // get the new message
        if (read)
            read = _pipe->read (msg_);
    }

    if (!read) {
        //  Initialise the output parameter to be a 0-byte message.
        rc = msg_->init ();
        errno_assert (rc == 0);

        errno = EAGAIN;
        return -1;
    }

    return 0;
}

bool zmq::channel_t::xhas_in ()
{
    if (!_pipe)
        return false;

    return _pipe->check_read ();
}

bool zmq::channel_t::xhas_out ()
{
    if (!_pipe)
        return false;

    return _pipe->check_write ();
}
