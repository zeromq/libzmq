/*
    Copyright (c) 2007-2010 iMatix Corporation

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the Lesser GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    Lesser GNU General Public License for more details.

    You should have received a copy of the Lesser GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __ZMQ_POLLER_BASE_HPP_INCLUDED__
#define __ZMQ_POLLER_BASE_HPP_INCLUDED__

#include "atomic_counter.hpp"

namespace zmq
{

    class poller_base_t
    {
    public:

        poller_base_t ();
        ~poller_base_t ();

        //  Returns load of the poller. Note that this function can be
        //  invoked from a different thread!
        int get_load ();

    protected:

        //  Called by individual poller implementations to manage the load.
        void adjust_load (int amount_);

    private:

        //  Load of the poller. Currently the number of file descriptors
        //  registered.
        atomic_counter_t load;

        poller_base_t (const poller_base_t&);
        void operator = (const poller_base_t&);
    };

}

#endif
