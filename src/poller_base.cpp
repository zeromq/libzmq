/* SPDX-License-Identifier: MPL-2.0 */

#include "precompiled.hpp"
#include "poller_base.hpp"
#include "i_poll_events.hpp"
#include "err.hpp"

zmq::poller_base_t::~poller_base_t ()
{
    //  Make sure there is no more load on the shutdown.
    zmq_assert (get_load () == 0);
}

int zmq::poller_base_t::get_load () const
{
    return _load.get ();
}

void zmq::poller_base_t::adjust_load (int amount_)
{
    if (amount_ > 0)
        _load.add (amount_);
    else if (amount_ < 0)
        _load.sub (-amount_);
}

void zmq::poller_base_t::add_timer (int timeout_, i_poll_events *sink_, int id_)
{
    uint64_t expiration = _clock.now_ms () + timeout_;
    timer_info_t info = {sink_, id_};
    _timers.insert (timers_t::value_type (expiration, info));
}

void zmq::poller_base_t::cancel_timer (i_poll_events *sink_, int id_)
{
    //  Complexity of this operation is O(n). We assume it is rarely used.
    for (timers_t::iterator it = _timers.begin (), end = _timers.end ();
         it != end; ++it)
        if (it->second.sink == sink_ && it->second.id == id_) {
            _timers.erase (it);
            return;
        }

    //  We should generally never get here. Calling 'cancel_timer ()' on
    //  an already expired or canceled timer (or even worse - on a timer which
    //  never existed, supplying bad sink_ and/or id_ values) does not make any
    //  sense.
    //  But in some edge cases this might happen. As described in issue #3645
    //  `timer_event ()` call from `execute_timers ()` might call `cancel_timer ()`
    //  on already canceled (deleted) timer.
    //  As soon as that is resolved an 'assert (false)' should be put here.
}

uint64_t zmq::poller_base_t::execute_timers ()
{
    //  Fast track.
    if (_timers.empty ())
        return 0;

    //  Get the current time.
    const uint64_t current = _clock.now_ms ();

    //  Execute the timers that are already due.
    uint64_t res = 0;
    timer_info_t timer_temp;
    timers_t::iterator it;

    do {
        it = _timers.begin ();

        //  If we have to wait to execute the item, same will be true for
        //  all the following items because multimap is sorted. Thus we can
        //  stop checking the subsequent timers.
        if (it->first > current) {
            res = it->first - current;
            break;
        }

        //  Save and remove the timer because timer_event() call might delete
        //  exactly this timer and then the iterator will be invalid.
        timer_temp = it->second;
        _timers.erase (it);

        //  Trigger the timer.
        timer_temp.sink->timer_event (timer_temp.id);

    } while (!_timers.empty ());

    //  Return the time to wait for the next timer (at least 1ms), or 0, if
    //  there are no more timers.
    return res;
}

zmq::worker_poller_base_t::worker_poller_base_t (const thread_ctx_t &ctx_) :
    _ctx (ctx_)
{
}

void zmq::worker_poller_base_t::stop_worker ()
{
    _worker.stop ();
}

void zmq::worker_poller_base_t::start (const char *name_)
{
    zmq_assert (get_load () > 0);
    _ctx.start_thread (_worker, worker_routine, this, name_);
}

void zmq::worker_poller_base_t::check_thread () const
{
#ifndef NDEBUG
    zmq_assert (!_worker.get_started () || _worker.is_current_thread ());
#endif
}

void zmq::worker_poller_base_t::worker_routine (void *arg_)
{
    (static_cast<worker_poller_base_t *> (arg_))->loop ();
}
