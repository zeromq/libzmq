/* SPDX-License-Identifier: MPL-2.0 */

#include "precompiled.hpp"
#include "manual_io.hpp"

#ifdef ZMQ_HAVE_MANUAL_IO
#include "err.hpp"

zmq::manual_io_t::manual_io_t (const thread_ctx_t &ctx_,
                              mailbox_t &term_mailbox_) :
    _poller (ctx_),
    _term_mailbox (term_mailbox_),
    _active (false),
    _done (false)
{
    const bool entered = enter ();
    zmq_assert (entered);
    _term_handle = _poller.add_fd (_term_mailbox.get_fd (), this);
    _poller.set_pollin (_term_handle);
    leave ();
}

zmq::manual_io_t::~manual_io_t ()
{
    const bool entered = enter ();
    zmq_assert (entered);
    _poller.rm_fd (_term_handle);
    leave ();
}

bool zmq::manual_io_t::enter ()
{
    if (!_sync.try_lock ()) {
        errno = EBUSY;
        return false;
    }
    //  mutex_t is recursive: reject same-thread reentry as well.
    if (_active) {
        _sync.unlock ();
        errno = EBUSY;
        return false;
    }
    _active = true;
    _owner.record_current_thread ();
    _poller.set_manual_thread (&_owner);
    return true;
}

void zmq::manual_io_t::leave ()
{
    zmq_assert (_active && _owner.is_current_thread ());
    _poller.set_manual_thread (NULL);
    _active = false;
    _sync.unlock ();
}

void zmq::manual_io_t::in_event ()
{
    command_t cmd;
    const int rc = _term_mailbox.recv (&cmd, 0);
    if (rc == -1 && (errno == EAGAIN || errno == EINTR))
        return;
    errno_assert (rc == 0);
    zmq_assert (cmd.type == command_t::done);
    _done = true;
}

void zmq::manual_io_t::out_event () { zmq_assert (false); }
void zmq::manual_io_t::timer_event (int) { zmq_assert (false); }
#endif
