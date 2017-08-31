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

zmq::timers_t::timers_t () : tag (0xCAFEDADA), next_timer_id (0)
{
}

zmq::timers_t::~timers_t ()
{
    //  Mark the timers as dead
    tag = 0xdeadbeef;
}

bool zmq::timers_t::check_tag ()
{
    return tag == 0xCAFEDADA;
}

int zmq::timers_t::add (size_t interval_, timers_timer_fn handler_, void *arg_)
{
    if (!handler_) {
        errno = EFAULT;
        return -1;
    }

    uint64_t when = clock.now_ms () + interval_;
    timer_t timer = {++next_timer_id, interval_, handler_, arg_};
    timers.insert (timersmap_t::value_type (when, timer));

    return timer.timer_id;
}

struct zmq::timers_t::match_by_id
{
    match_by_id (int timer_id_) : timer_id (timer_id_) {}

    bool operator() (timersmap_t::value_type const &entry) const
    {
        return entry.second.timer_id == timer_id;
    }

  private:
    int timer_id;
};

int zmq::timers_t::cancel (int timer_id_)
{
    // check first if timer exists at all
    if (timers.end ()
        == std::find_if (timers.begin (), timers.end (),
                         match_by_id (timer_id_))) {
        errno = EINVAL;
        return -1;
    }

    // check if timer was already canceled
    if (cancelled_timers.count (timer_id_)) {
        errno = EINVAL;
        return -1;
    }

    cancelled_timers.insert (timer_id_);

    return 0;
}

int zmq::timers_t::set_interval (int timer_id_, size_t interval_)
{
    const timersmap_t::iterator end = timers.end ();
    const timersmap_t::iterator it =
      std::find_if (timers.begin (), end, match_by_id (timer_id_));
    if (it != end) {
        timer_t timer = it->second;
        timer.interval = interval_;
        uint64_t when = clock.now_ms () + interval_;
        timers.erase (it);
        timers.insert (timersmap_t::value_type (when, timer));

        return 0;
    }

    errno = EINVAL;
    return -1;
}

int zmq::timers_t::reset (int timer_id_)
{
    const timersmap_t::iterator end = timers.end ();
    const timersmap_t::iterator it =
      std::find_if (timers.begin (), end, match_by_id (timer_id_));
    if (it != end) {
        timer_t timer = it->second;
        uint64_t when = clock.now_ms () + timer.interval;
        timers.erase (it);
        timers.insert (timersmap_t::value_type (when, timer));

        return 0;
    }

    errno = EINVAL;
    return -1;
}

long zmq::timers_t::timeout ()
{
    timersmap_t::iterator it = timers.begin ();

    uint64_t now = clock.now_ms ();

    while (it != timers.end ()) {
        cancelled_timers_t::iterator cancelled_it =
          cancelled_timers.find (it->second.timer_id);

        //  Live timer, lets return the timeout
        if (cancelled_it == cancelled_timers.end ()) {
            if (it->first > now)
                return (long) (it->first - now);
            else
                return 0;
        }

        // Let's remove it from the beginning of the list
        timersmap_t::iterator old = it;
        ++it;
        timers.erase (old);
        cancelled_timers.erase (cancelled_it);
    }

    //  Wait forever as no timers are alive
    return -1;
}

int zmq::timers_t::execute ()
{
    timersmap_t::iterator it = timers.begin ();

    uint64_t now = clock.now_ms ();

    while (it != timers.end ()) {
        cancelled_timers_t::iterator cancelled_it =
          cancelled_timers.find (it->second.timer_id);

        //  Dead timer, lets remove it and continue
        if (cancelled_it != cancelled_timers.end ()) {
            timersmap_t::iterator old = it;
            ++it;
            timers.erase (old);
            cancelled_timers.erase (cancelled_it);
            continue;
        }

        //  Map is ordered, if we have to wait for current timer we can stop.
        if (it->first > now)
            break;

        timer_t timer = it->second;

        timer.handler (timer.timer_id, timer.arg);

        timersmap_t::iterator old = it;
        ++it;
        timers.erase (old);
        timers.insert (timersmap_t::value_type (now + timer.interval, timer));
    }

    return 0;
}
