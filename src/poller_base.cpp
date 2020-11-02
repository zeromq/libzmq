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
