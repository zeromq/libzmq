/* SPDX-License-Identifier: MPL-2.0 */

#include "precompiled.hpp"
#include "sub.hpp"
#include "msg.hpp"

zmq::sub_t::sub_t (class ctx_t *parent_, uint32_t tid_, int sid_) :
    xsub_t (parent_, tid_, sid_)
{
    options.type = ZMQ_SUB;

    //  Switch filtering messages on (as opposed to XSUB which where the
    //  filtering is off).
    options.filter = true;
}

zmq::sub_t::~sub_t ()
{
}

int zmq::sub_t::xsetsockopt (int option_,
                             const void *optval_,
                             size_t optvallen_)
{
    if (option_ != ZMQ_SUBSCRIBE && option_ != ZMQ_UNSUBSCRIBE) {
        errno = EINVAL;
        return -1;
    }

    //  Create the subscription message.
    msg_t msg;
    int rc;
    const unsigned char *data = static_cast<const unsigned char *> (optval_);
    if (option_ == ZMQ_SUBSCRIBE) {
        rc = msg.init_subscribe (optvallen_, data);
    } else {
        rc = msg.init_cancel (optvallen_, data);
    }
    errno_assert (rc == 0);

    //  Pass it further on in the stack.
    rc = xsub_t::xsend (&msg);
    return close_and_return (&msg, rc);
}

int zmq::sub_t::xsend (msg_t *)
{
    //  Override the XSUB's send.
    errno = ENOTSUP;
    return -1;
}

bool zmq::sub_t::xhas_out ()
{
    //  Override the XSUB's send.
    return false;
}
