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
#include "timers.hpp"
#include "err.hpp"

#include <algorithm>

zmq::timers_t::timers_t () : _tag (0xCAFEDADA), _next_timer_id (0)
{
}

zmq::timers_t::~timers_t ()
{
    //  Mark the timers as dead
    _tag = 0xdeadbeef;
}

bool zmq::timers_t::check_tag () const
{
    return _tag == 0xCAFEDADA;
}

int zmq::timers_t::add (size_t interval_, timers_timer_fn handler_, void *arg_)
{
    if (handler_ == NULL) {
        errno = EFAULT;
        return -1;
    }

    uint64_t when = _clock.now_ms () + interval_;
    timer_t timer = {++_next_timer_id, interval_, handler_, arg_};
    _timers.insert (timersmap_t::value_type (when, timer));

    return timer.timer_id;
}

struct zmq::timers_t::match_by_id
{
    match_by_id (int timer_id_) : _timer_id (timer_id_) {}

    bool operator() (timersmap_t::value_type const &entry_) const
    {
        return entry_.second.timer_id == _timer_id;
    }

  private:
    int _timer_id;
};

int zmq::timers_t::cancel (int timer_id_)
{
    // check first if timer exists at all
    if (_timers.end ()
        == std::find_if (_timers.begin (), _timers.end (),
                         match_by_id (timer_id_))) {
        errno = EINVAL;
        return -1;
    }

    // check if timer was already canceled
    if (_cancelled_timers.count (timer_id_)) {
        errno = EINVAL;
        return -1;
    }

    _cancelled_timers.insert (timer_id_);

    return 0;
}

int zmq::timers_t::set_interval (int timer_id_, size_t interval_)
{
    const timersmap_t::iterator end = _timers.end ();
    const timersmap_t::iterator it =
      std::find_if (_timers.begin (), end, match_by_id (timer_id_));
    if (it != end) {
        timer_t timer = it->second;
        timer.interval = interval_;
        uint64_t when = _clock.now_ms () + interval_;
        _timers.erase (it);
        _timers.insert (timersmap_t::value_type (when, timer));

        return 0;
    }

    errno = EINVAL;
    return -1;
}

int zmq::timers_t::reset (int timer_id_)
{
    const timersmap_t::iterator end = _timers.end ();
    const timersmap_t::iterator it =
      std::find_if (_timers.begin (), end, match_by_id (timer_id_));
    if (it != end) {
        timer_t timer = it->second;
        uint64_t when = _clock.now_ms () + timer.interval;
        _timers.erase (it);
        _timers.insert (timersmap_t::value_type (when, timer));

        return 0;
    }

    errno = EINVAL;
    return -1;
}

long zmq::timers_t::timeout ()
{
    const uint64_t now = _clock.now_ms ();
    long res = -1;

    const timersmap_t::iterator begin = _timers.begin ();
    const timersmap_t::iterator end = _timers.end ();
    timersmap_t::iterator it = begin;
    for (; it != end; ++it) {
        if (0 == _cancelled_timers.erase (it->second.timer_id)) {
            //  Live timer, lets return the timeout
            res = std::max (static_cast<long> (it->first - now), 0l);
            break;
        }
    }

    //  Remove timed-out timers
    _timers.erase (begin, it);

    return res;
}

int zmq::timers_t::execute ()
{
    const uint64_t now = _clock.now_ms ();

    const timersmap_t::iterator begin = _timers.begin ();
    const timersmap_t::iterator end = _timers.end ();
    timersmap_t::iterator it = _timers.begin ();
    for (; it != end; ++it) {
        if (0 == _cancelled_timers.erase (it->second.timer_id)) {
            //  Timer is not cancelled

            //  Map is ordered, if we have to wait for current timer we can stop.
            if (it->first > now)
                break;

            const timer_t &timer = it->second;

            timer.handler (timer.timer_id, timer.arg);

            _timers.insert (
              timersmap_t::value_type (now + timer.interval, timer));
        }
    }
    _timers.erase (begin, it);

    return 0;
}
