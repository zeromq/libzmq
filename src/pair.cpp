/* SPDX-License-Identifier: MPL-2.0 */

#include "precompiled.hpp"
#include "macros.hpp"
#include "pair.hpp"
#include "err.hpp"
#include "pipe.hpp"
#include "msg.hpp"

zmq::pair_t::pair_t (class ctx_t *parent_, uint32_t tid_, int sid_) :
    socket_base_t (parent_, tid_, sid_), _pipe (NULL)
{
    options.type = ZMQ_PAIR;
}

zmq::pair_t::~pair_t ()
{
    zmq_assert (!_pipe);
}

void zmq::pair_t::xattach_pipe (pipe_t *pipe_,
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

void zmq::pair_t::xpipe_terminated (pipe_t *pipe_)
{
    if (pipe_ == _pipe) {
        _pipe = NULL;
    }
}

void zmq::pair_t::xread_activated (pipe_t *)
{
    //  There's just one pipe. No lists of active and inactive pipes.
    //  There's nothing to do here.
}

void zmq::pair_t::xwrite_activated (pipe_t *)
{
    //  There's just one pipe. No lists of active and inactive pipes.
    //  There's nothing to do here.
}

int zmq::pair_t::xsend (msg_t *msg_)
{
    if (!_pipe || !_pipe->write (msg_)) {
        errno = EAGAIN;
        return -1;
    }

    if (!(msg_->flags () & msg_t::more))
        _pipe->flush ();

    //  Detach the original message from the data buffer.
    const int rc = msg_->init ();
    errno_assert (rc == 0);

    return 0;
}

int zmq::pair_t::xrecv (msg_t *msg_)
{
    //  Deallocate old content of the message.
    int rc = msg_->close ();
    errno_assert (rc == 0);

    if (!_pipe || !_pipe->read (msg_)) {
        //  Initialise the output parameter to be a 0-byte message.
        rc = msg_->init ();
        errno_assert (rc == 0);

        errno = EAGAIN;
        return -1;
    }
    return 0;
}

bool zmq::pair_t::xhas_in ()
{
    if (!_pipe)
        return false;

    return _pipe->check_read ();
}

bool zmq::pair_t::xhas_out ()
{
    if (!_pipe)
        return false;

    return _pipe->check_write ();
}
