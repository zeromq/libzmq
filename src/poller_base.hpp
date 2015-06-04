/*
    Copyright (c) 2007-2015 Contributors as noted in the AUTHORS file

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

#ifndef __ZMQ_POLLER_BASE_HPP_INCLUDED__
#define __ZMQ_POLLER_BASE_HPP_INCLUDED__

#include <map>

#include "clock.hpp"
#include "atomic_counter.hpp"

namespace zmq
{

    struct i_poll_events;

    class poller_base_t
    {
    public:

        poller_base_t ();
        virtual ~poller_base_t ();

        //  Returns load of the poller. Note that this function can be
        //  invoked from a different thread!
        int get_load ();

        //  Add a timeout to expire in timeout_ milliseconds. After the
        //  expiration timer_event on sink_ object will be called with
        //  argument set to id_.
        void add_timer (int timeout_, zmq::i_poll_events *sink_, int id_);

        //  Cancel the timer created by sink_ object with ID equal to id_.
        void cancel_timer (zmq::i_poll_events *sink_, int id_);

    protected:

        //  Called by individual poller implementations to manage the load.
        void adjust_load (int amount_);

        //  Executes any timers that are due. Returns number of milliseconds
        //  to wait to match the next timer or 0 meaning "no timers".
        uint64_t execute_timers ();

    private:

        //  Clock instance private to this I/O thread.
        clock_t clock;

        //  List of active timers.
        struct timer_info_t
        {
            zmq::i_poll_events *sink;
            int id;
        };
        typedef std::multimap <uint64_t, timer_info_t> timers_t;
        timers_t timers;

        //  Load of the poller. Currently the number of file descriptors
        //  registered.
        atomic_counter_t load;

        poller_base_t (const poller_base_t&);
        const poller_base_t &operator = (const poller_base_t&);
    };

}

#endif
