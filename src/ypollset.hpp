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

#ifndef __ZMQ_YPOLLSET_HPP_INCLUDED__
#define __ZMQ_YPOLLSET_HPP_INCLUDED__

#include "i_signaler.hpp"
#include "simple_semaphore.hpp"
#include "atomic_bitmap.hpp"

namespace zmq
{

    //  ypollset allows for rapid polling for up to constant number of  
    //  different signals each produced by a different thread. The number of
    //  possible signals is platform-dependent.

    class ypollset_t : public i_signaler
    {
    public:

        ypollset_t ();
        ~ypollset_t ();

        //  i_signaler interface implementation.
        void signal (int signal_);
        uint64_t poll ();
        uint64_t check ();
        fd_t get_fd ();

    private:

        //  Internal representation of signal bitmap.
        typedef atomic_bitmap_t::bitmap_t signals_t;

        //  Wait signal is carried in the most significant bit of integer.
        enum {wait_signal = sizeof (signals_t) * 8 - 1};

        //  The bits of the pollset.
        atomic_bitmap_t bits;

        //  Used by thread waiting for signals to sleep if there are no
        //  signals available.
        simple_semaphore_t sem;

        //  Disable copying of ypollset object.
        ypollset_t (const ypollset_t&);
        void operator = (const ypollset_t&);
    };

}

#endif
