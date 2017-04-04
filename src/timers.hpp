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

#ifndef __ZMQ_TIMERS_HPP_INCLUDED__
#define __ZMQ_TIMERS_HPP_INCLUDED__

#include <stddef.h>
#include <map>
#include <set>

#include "clock.hpp"

namespace zmq
{
    typedef void (timers_timer_fn)(
        int timer_id, void *arg);

        class timers_t
        {
        public:
            timers_t ();
            ~timers_t ();

            //  Add timer to the set, timer repeats forever, or until cancel is called.
            //  Returns a timer_id that is used to cancel the timer.
            //  Returns -1 if there was an error.
            int add (size_t interval, timers_timer_fn handler, void* arg);

            //  Set the interval of the timer.
            //  This method is slow, cancelling exsting and adding a new timer yield better performance.
            //  Returns 0 on success and -1 on error.
            int set_interval (int timer_id, size_t interval);

            //  Reset the timer.
            //  This method is slow, cancelling exsting and adding a new timer yield better performance.
            //  Returns 0 on success and -1 on error.
            int reset (int timer_id);

            //  Cancel a timer.
            //  Returns 0 on success and -1 on error.
            int cancel (int timer_id);

            //  Returns the time in millisecond until the next timer.
            //  Returns -1 if no timer is due.
            long timeout ();

            //  Execute timers.
            //  Return 0 if all succeed and -1 if error.
            int execute ();

            //  Return false if object is not a timers class.
            bool check_tag ();

        private:

            //  Used to check whether the object is a timers class.
            uint32_t tag;

            int next_timer_id;

            //  Clock instance.
            clock_t clock;

            typedef struct timer_t {
                int timer_id;
                size_t interval;
                timers_timer_fn *handler;
                void *arg;
            } timer_t;

            typedef std::multimap <uint64_t, timer_t> timersmap_t;
            timersmap_t timers;

            typedef std::set<int> cancelled_timers_t;
            cancelled_timers_t cancelled_timers;

            timers_t (const timers_t&);
            const timers_t &operator = (const timers_t&);
        };
    }

    #endif
