/*
    Copyright (c) 2007-2009 FastMQ Inc.

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

#include "ypollset.hpp"

zmq::ypollset_t::ypollset_t ()
{
}

zmq::ypollset_t::~ypollset_t ()
{
}

void zmq::ypollset_t::signal (int signal_)
{
    zmq_assert (signal_ >= 0 && signal_ < wait_signal);
    if (bits.btsr (signal_, wait_signal))
        sem.post (); 
}

uint64_t zmq::ypollset_t::poll ()
{
    signals_t result = 0;
    while (!result) {
        result = bits.izte (signals_t (1) << wait_signal, 0);
        if (!result) {
            sem.wait ();
            result = bits.xchg (0);
        }

        //  If btsr was really atomic, result would never be 0 at this
        //  point, i.e. no looping would be possible. However, to
        //  support even CPU architectures without CAS instruction
        //  we allow btsr to be composed of two independent atomic
        //  operation (set and reset). In such case looping can occur
        //  sporadically.
    }
    return (uint64_t) result;      
}

uint64_t zmq::ypollset_t::check ()
{
    return (uint64_t) bits.xchg (0);
}
