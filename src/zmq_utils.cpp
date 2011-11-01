/*
    Copyright (c) 2009-2011 250bpm s.r.o.
    Copyright (c) 2007-2009 iMatix Corporation
    Copyright (c) 2007-2011 Other contributors as noted in the AUTHORS file

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "platform.hpp"

#include "../include/zmq_utils.h"

#include <stdlib.h>

#include "stdint.hpp"
#include "clock.hpp"
#include "err.hpp"

#if !defined ZMQ_HAVE_WINDOWS
#include <unistd.h>
#else
#include "windows.hpp"
#endif

void zmq_sleep (int seconds_)
{
#if defined ZMQ_HAVE_WINDOWS
    Sleep (seconds_ * 1000);
#else
    sleep (seconds_);
#endif
}

void *zmq_stopwatch_start ()
{
    uint64_t *watch = (uint64_t*) malloc (sizeof (uint64_t));
    alloc_assert (watch);
    *watch = zmq::clock_t::now_us ();
    return (void*) watch;
}

unsigned long zmq_stopwatch_stop (void *watch_)
{
    uint64_t end = zmq::clock_t::now_us ();
    uint64_t start = *(uint64_t*) watch_;
    free (watch_);
    return (unsigned long) (end - start);
}
