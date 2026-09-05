/* SPDX-License-Identifier: MPL-2.0 */

#include "precompiled.hpp"
#include "manual_io.hpp"

#ifdef ZMQ_HAVE_MANUAL_IO
#include "err.hpp"
#include "object.hpp"
#include <new>

zmq::manual_io_t::manual_io_t (const thread_ctx_t &ctx_,
                              mailbox_t &term_mailbox_) :
    _poller (ctx_),
    _term_mailbox (term_mailbox_),
    _active (false),
    _done (false),
    _state (NULL),
    _term_receiver (NULL),
    _pending_first (true)
{
    const bool entered = enter ();
    zmq_assert (entered);
    _term_receiver = new (std::nothrow) manual_mailbox_t (*this, _term_mailbox);
    alloc_assert (_term_receiver);
    _term_handle = _poller.add_fd (_term_mailbox.get_fd (), _term_receiver);
    _poller.set_pollin (_term_handle);
    leave ();
}

zmq::manual_io_t::~manual_io_t ()
{
    const bool entered = enter ();
    zmq_assert (entered);
    _poller.rm_fd (_term_handle);
    LIBZMQ_DELETE (_term_receiver);
    zmq_assert (_pending.empty ());
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
    zmq_assert (false);
}

void zmq::manual_io_t::out_event () { zmq_assert (false); }
void zmq::manual_io_t::timer_event (int) { zmq_assert (false); }

int zmq::manual_io_t::run (const zmq_ctx_step_budget_t &budget_,
                          zmq_ctx_step_result_t *result_)
{
    zmq_assert (_active && _owner.is_current_thread () && !_state);
    poller_step_t state;
    state.max_events = budget_.max_events;
    state.max_commands = budget_.max_commands;
    state.max_timers = budget_.max_timers;
    _state = &state;

    const bool had_pending = !_pending.empty ();
    const bool pending_first = _pending_first;
    if (had_pending)
        _pending_first = !_pending_first;
    if (pending_first)
        resume_pending ();

    if (!state.error)
        _poller.run_once (had_pending ? 0 : budget_.timeout_ms, &state);
    if (!pending_first && !state.error)
        resume_pending ();
    //  A timer that expired during the OS wait must fire in this step.
    if (!state.error)
        _poller.execute_timers (&state);

    if (!_pending.empty ()) {
        state.more = true;
        if (!state.error)
            state.exhausted = true;
    }
    //  Observe, without dispatching, whether an exact event cap left work.
    if (!state.error && !state.event_available ()) {
        state.probe = true;
        _poller.run_once (0, &state);
    }

    const int next = state.more ? 0 : _poller.next_timer_delay ();
    if (result_) {
        result_->events_processed = state.events;
        result_->commands_processed = state.commands;
        result_->timers_processed = state.timers;
        result_->flags = (state.more ? ZMQ_CTX_STEP_MORE_WORK : 0)
                         | (state.exhausted ? ZMQ_CTX_STEP_BUDGET_EXHAUSTED : 0)
                         | (!state.progress () && !state.more ? ZMQ_CTX_STEP_IDLE : 0);
        result_->next_timeout_ms = next;
    }
    _state = NULL;
    if (state.error) {
        errno = state.error;
        return -1;
    }
    return static_cast<int> (std::min<uint64_t> (
      uint64_t (state.events) + state.commands + state.timers, INT_MAX));
}

void zmq::manual_io_t::defer (manual_mailbox_t *mailbox_)
{
    if (!mailbox_->_queued) {
        mailbox_->_queued = true;
        _pending.push_back (mailbox_);
    }
}

void zmq::manual_io_t::cancel (manual_mailbox_t *mailbox_)
{
    if (mailbox_->_queued) {
        _pending.remove (mailbox_);
        mailbox_->_queued = false;
    }
}

void zmq::manual_io_t::resume_pending ()
{
    //  A finite snapshot; a receiver that requeues goes behind its peers.
    size_t remaining = _pending.size ();
    while (remaining-- && !_pending.empty () && _state->event_available ()
           && !_state->error) {
        manual_mailbox_t *receiver = _pending.front ();
        _pending.pop_front ();
        receiver->_queued = false;
        _state->event ();
        receiver->dispatch (false);
        //  dispatch may have deleted the receiver.
    }
}

zmq::manual_mailbox_t::manual_mailbox_t (manual_io_t &driver_, i_mailbox &mailbox_,
                                        callback_t callback_, void *arg_) :
    _driver (driver_), _mailbox (mailbox_), _callback (callback_), _arg (arg_),
    _has_command (false), _queued (false)
{
}

zmq::manual_mailbox_t::~manual_mailbox_t ()
{
    zmq_assert (!_has_command);
    _driver.cancel (this);
}

void zmq::manual_mailbox_t::dispatch (bool notification_)
{
    if (_callback)
        _callback (this, notification_);
    else
        drain ();
}

void zmq::manual_mailbox_t::in_event ()
{
    if (!_queued)
        dispatch (true);
}

void zmq::manual_mailbox_t::out_event () { zmq_assert (false); }
void zmq::manual_mailbox_t::timer_event (int) { zmq_assert (false); }

bool zmq::manual_mailbox_t::drain ()
{
    poller_step_t &state = _driver.state ();
    while (true) {
        if (!_has_command) {
            const int rc = _mailbox.recv (&_command, 0);
            if (rc == -1) {
                errno_assert (errno == EAGAIN || errno == EINTR);
                if (errno == EINTR) {
                    state.error = EINTR;
                    _driver.defer (this);
                    return false;
                }
                return true;
            }
            _has_command = true;
        }
        if (!state.command_available ()) {
            state.defer ();
            _driver.defer (this);
            return false;
        }
        _has_command = false;
        poller_step_t::increment (state.commands);
        if (_command.type == command_t::done) {
            zmq_assert (!_command.destination);
            _driver.completed ();
        } else
            _command.destination->process_command (_command);
    }
}
#endif
