/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_POLLER_STEP_HPP_INCLUDED__
#define __ZMQ_POLLER_STEP_HPP_INCLUDED__

#include "stdint.hpp"
#include "macros.hpp"
#include <algorithm>
#include <climits>

namespace zmq
{
//  Private accounting policy. Threaded template instantiations never access it.
struct ZMQ_PRIVATE poller_step_t
{
    poller_step_t () :
        max_events (0),
        max_commands (0),
        max_timers (0),
        events (0),
        commands (0),
        timers (0),
        more (false),
        exhausted (false),
        probe (false),
        error (0)
    {
    }

    uint32_t max_events, max_commands, max_timers;
    uint32_t events, commands, timers;
    bool more, exhausted, probe;
    int error;

    static void increment (uint32_t &value_)
    {
        if (value_ != UINT32_MAX)
            ++value_;
    }

    bool event_available () const
    {
        return !probe && (!max_events || events < max_events);
    }
    bool command_available () const
    {
        return !max_commands || commands < max_commands;
    }
    bool timer_available () const
    {
        return !probe && (!max_timers || timers < max_timers);
    }
    void defer () { more = exhausted = true; }
    bool progress () const { return events || commands || timers; }
    int event_batch (int maximum_) const
    {
        //  A one-record observation is needed even when the allowance is zero.
        if (!event_available ())
            return 1;
        return max_events ? static_cast<int> (std::min<uint32_t> (
                              max_events - events, maximum_))
                          : maximum_;
    }
    bool event ()
    {
        if (probe) {
            more = true;
            if (max_events && events >= max_events)
                exhausted = true;
            return false;
        }
        if (!event_available ()) {
            defer ();
            return false;
        }
        increment (events);
        return true;
    }
};
}
#endif
