/* SPDX-License-Identifier: MPL-2.0 */

#include "precompiled.hpp"
#include "macros.hpp"
#include "dealer.hpp"
#include "err.hpp"
#include "msg.hpp"

zmq::dealer_t::dealer_t (class ctx_t *parent_, uint32_t tid_, int sid_) :
    socket_base_t (parent_, tid_, sid_), _probe_router (false)
{
    options.type = ZMQ_DEALER;
    options.can_send_hello_msg = true;
    options.can_recv_hiccup_msg = true;
}

zmq::dealer_t::~dealer_t ()
{
}

void zmq::dealer_t::xattach_pipe (pipe_t *pipe_,
                                  bool subscribe_to_all_,
                                  bool locally_initiated_)
{
    LIBZMQ_UNUSED (subscribe_to_all_);
    LIBZMQ_UNUSED (locally_initiated_);

    zmq_assert (pipe_);

    if (_probe_router) {
        msg_t probe_msg;
        int rc = probe_msg.init ();
        errno_assert (rc == 0);

        rc = pipe_->write (&probe_msg);
        // zmq_assert (rc) is not applicable here, since it is not a bug.
        LIBZMQ_UNUSED (rc);

        pipe_->flush ();

        rc = probe_msg.close ();
        errno_assert (rc == 0);
    }

    _fq.attach (pipe_);
    _lb.attach (pipe_);
}

int zmq::dealer_t::xsetsockopt (int option_,
                                const void *optval_,
                                size_t optvallen_)
{
    const bool is_int = (optvallen_ == sizeof (int));
    int value = 0;
    if (is_int)
        memcpy (&value, optval_, sizeof (int));

    switch (option_) {
        case ZMQ_PROBE_ROUTER:
            if (is_int && value >= 0) {
                _probe_router = (value != 0);
                return 0;
            }
            break;

        default:
            break;
    }

    errno = EINVAL;
    return -1;
}

int zmq::dealer_t::xsend (msg_t *msg_)
{
    return sendpipe (msg_, NULL);
}

int zmq::dealer_t::xrecv (msg_t *msg_)
{
    return recvpipe (msg_, NULL);
}

bool zmq::dealer_t::xhas_in ()
{
    return _fq.has_in ();
}

bool zmq::dealer_t::xhas_out ()
{
    return _lb.has_out ();
}

void zmq::dealer_t::xread_activated (pipe_t *pipe_)
{
    _fq.activated (pipe_);
}

void zmq::dealer_t::xwrite_activated (pipe_t *pipe_)
{
    _lb.activated (pipe_);
}

void zmq::dealer_t::xpipe_terminated (pipe_t *pipe_)
{
    _fq.pipe_terminated (pipe_);
    _lb.pipe_terminated (pipe_);
}

int zmq::dealer_t::sendpipe (msg_t *msg_, pipe_t **pipe_)
{
    return _lb.sendpipe (msg_, pipe_);
}

int zmq::dealer_t::recvpipe (msg_t *msg_, pipe_t **pipe_)
{
    return _fq.recvpipe (msg_, pipe_);
}
