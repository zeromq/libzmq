/* SPDX-License-Identifier: MPL-2.0 */

#include "precompiled.hpp"
#include "mailbox_safe.hpp"
#include "clock.hpp"
#include "err.hpp"

#include <algorithm>

zmq::mailbox_safe_t::mailbox_safe_t (mutex_t *sync_) : _sync (sync_)
{
    //  Get the pipe into passive state. That way, if the users starts by
    //  polling on the associated file descriptor it will get woken up when
    //  new command is posted.
    const bool ok = _cpipe.check_read ();
    zmq_assert (!ok);
}

zmq::mailbox_safe_t::~mailbox_safe_t ()
{
    //  TODO: Retrieve and deallocate commands inside the cpipe.

    // Work around problem that other threads might still be in our
    // send() method, by waiting on the mutex before disappearing.
    _sync->lock ();
    _sync->unlock ();
}

void zmq::mailbox_safe_t::add_signaler (signaler_t *signaler_)
{
    _signalers.push_back (signaler_);
}

void zmq::mailbox_safe_t::remove_signaler (signaler_t *signaler_)
{
    // TODO: make a copy of array and signal outside the lock
    const std::vector<zmq::signaler_t *>::iterator end = _signalers.end ();
    const std::vector<signaler_t *>::iterator it =
      std::find (_signalers.begin (), end, signaler_);

    if (it != end)
        _signalers.erase (it);
}

void zmq::mailbox_safe_t::clear_signalers ()
{
    _signalers.clear ();
}

void zmq::mailbox_safe_t::send (const command_t &cmd_)
{
    _sync->lock ();
    _cpipe.write (cmd_, false);
    const bool ok = _cpipe.flush ();

    if (!ok) {
        _cond_var.broadcast ();

        for (std::vector<signaler_t *>::iterator it = _signalers.begin (),
                                                 end = _signalers.end ();
             it != end; ++it) {
            (*it)->send ();
        }
    }

    _sync->unlock ();
}

int zmq::mailbox_safe_t::recv (command_t *cmd_, int timeout_)
{
    //  Try to get the command straight away.
    if (_cpipe.read (cmd_))
        return 0;

    //  If the timeout is zero, it will be quicker to release the lock, giving other a chance to send a command
    //  and immediately relock it.
    if (timeout_ == 0) {
        _sync->unlock ();
        _sync->lock ();
    } else {
        //  Wait for signal from the command sender.
        const int rc = _cond_var.wait (_sync, timeout_);
        if (rc == -1) {
            errno_assert (errno == EAGAIN || errno == EINTR);
            return -1;
        }
    }

    //  Another thread may already fetch the command
    const bool ok = _cpipe.read (cmd_);

    if (!ok) {
        errno = EAGAIN;
        return -1;
    }

    return 0;
}
