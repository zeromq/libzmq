/* SPDX-License-Identifier: MPL-2.0 */

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
