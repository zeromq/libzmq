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

#ifndef __ZMQ_CLOCK_HPP_INCLUDED__
#define __ZMQ_CLOCK_HPP_INCLUDED__

#include "stdint.hpp"

namespace zmq
{

    class clock_t
    {
    public:

        clock_t ();
        ~clock_t ();

        //  CPU's timestamp counter. Returns 0 if it's not available.
        static uint64_t rdtsc ();

        //  High precision timestamp.
        static uint64_t now_us ();

        //  Low precision timestamp. In tight loops generating it can be
        //  10 to 100 times faster than the high precision timestamp.
        uint64_t now_ms ();

    private:

        //  TSC timestamp of when last time measurement was made.
        uint64_t last_tsc;

        //  Physical time corresponding to the TSC above (in milliseconds).
        uint64_t last_time;

        clock_t (const clock_t&);
        const clock_t &operator = (const clock_t&);
    };

}

#endif
