/* SPDX-License-Identifier: MPL-2.0 */

#include "precompiled.hpp"
#include "rep.hpp"
#include "err.hpp"
#include "msg.hpp"

zmq::rep_t::rep_t (class ctx_t *parent_, uint32_t tid_, int sid_) :
    router_t (parent_, tid_, sid_),
    _sending_reply (false),
    _request_begins (true)
{
    options.type = ZMQ_REP;
}

zmq::rep_t::~rep_t ()
{
}

int zmq::rep_t::xsend (msg_t *msg_)
{
    //  If we are in the middle of receiving a request, we cannot send reply.
    if (!_sending_reply) {
        errno = EFSM;
        return -1;
    }

    const bool more = (msg_->flags () & msg_t::more) != 0;

    //  Push message to the reply pipe.
    const int rc = router_t::xsend (msg_);
    if (rc != 0)
        return rc;

    //  If the reply is complete flip the FSM back to request receiving state.
    if (!more)
        _sending_reply = false;

    return 0;
}

int zmq::rep_t::xrecv (msg_t *msg_)
{
    //  If we are in middle of sending a reply, we cannot receive next request.
    if (_sending_reply) {
        errno = EFSM;
        return -1;
    }

    //  First thing to do when receiving a request is to copy all the labels
    //  to the reply pipe.
    if (_request_begins) {
        while (true) {
            int rc = router_t::xrecv (msg_);
            if (rc != 0)
                return rc;

            if ((msg_->flags () & msg_t::more)) {
                //  Empty message part delimits the traceback stack.
                const bool bottom = (msg_->size () == 0);

                //  Push it to the reply pipe.
                rc = router_t::xsend (msg_);
                errno_assert (rc == 0);

                if (bottom)
                    break;
            } else {
                //  If the traceback stack is malformed, discard anything
                //  already sent to pipe (we're at end of invalid message).
                rc = router_t::rollback ();
                errno_assert (rc == 0);
            }
        }
        _request_begins = false;
    }

    //  Get next message part to return to the user.
    const int rc = router_t::xrecv (msg_);
    if (rc != 0)
        return rc;

    //  If whole request is read, flip the FSM to reply-sending state.
    if (!(msg_->flags () & msg_t::more)) {
        _sending_reply = true;
        _request_begins = true;
    }

    return 0;
}

bool zmq::rep_t::xhas_in ()
{
    if (_sending_reply)
        return false;

    return router_t::xhas_in ();
}

bool zmq::rep_t::xhas_out ()
{
    if (!_sending_reply)
        return false;

    return router_t::xhas_out ();
}
