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

#include <algorithm>

#include "../include/zmq.h"

#if defined ZMQ_HAVE_WINDOWS
#include "windows.hpp"
#else
#include <unistd.h>
#endif

#include "app_thread.hpp"
#include "dispatcher.hpp"
#include "err.hpp"
#include "pipe.hpp"
#include "config.hpp"
#include "socket_base.hpp"

//  If the RDTSC is available we use it to prevent excessive
//  polling for commands. The nice thing here is that it will work on any
//  system with x86 architecture and gcc or MSVC compiler.
#if (defined __GNUC__ && (defined __i386__ || defined __x86_64__)) ||\
    (defined _MSC_VER && (defined _M_IX86 || defined _M_X64))
#define ZMQ_DELAY_COMMANDS
#endif

zmq::app_thread_t::app_thread_t (dispatcher_t *dispatcher_, int thread_slot_) :
    object_t (dispatcher_, thread_slot_),
    tid (0),
    last_processing_time (0)
{
}

zmq::app_thread_t::~app_thread_t ()
{
    //  Destroy all the sockets owned by this application thread.
    for (sockets_t::iterator it = sockets.begin (); it != sockets.end (); it ++)
        delete *it;
}

zmq::i_signaler *zmq::app_thread_t::get_signaler ()
{
    return &pollset;
}

bool zmq::app_thread_t::is_current ()
{
    return !sockets.empty () && tid == getpid ();
}

bool zmq::app_thread_t::make_current ()
{
    //  If there are object managed by this slot we cannot assign the slot
    //  to a different thread.
    if (!sockets.empty ())
        return false;

    tid = getpid ();
    return true;
}

void zmq::app_thread_t::process_commands (bool block_)
{
    ypollset_t::signals_t signals;
    if (block_)
        signals = pollset.poll ();
    else {

#if defined ZMQ_DELAY_COMMANDS
        //  Optimised version of command processing - it doesn't have to check
        //  for incoming commands each time. It does so only if certain time
        //  elapsed since last command processing. Command delay varies
        //  depending on CPU speed: It's ~1ms on 3GHz CPU, ~2ms on 1.5GHz CPU
        //  etc. The optimisation makes sense only on platforms where getting
        //  a timestamp is a very cheap operation (tens of nanoseconds).

        //  Get timestamp counter.
#if defined __GNUC__
        uint32_t low;
        uint32_t high;
        __asm__ volatile ("rdtsc" : "=a" (low), "=d" (high));
        uint64_t current_time = (uint64_t) high << 32 | low;
#elif defined _MSC_VER
        uint64_t current_time = __rdtsc ();
#else
#error
#endif

        //  Check whether certain time have elapsed since last command
        //  processing.
        if (current_time - last_processing_time <= max_command_delay)
            return;
        last_processing_time = current_time;
#endif

        //  Check whether there are any commands pending for this thread.
        signals = pollset.check ();
    }

    if (signals) {

        //  Traverse all the possible sources of commands and process
        //  all the commands from all of them.
        for (int i = 0; i != thread_slot_count (); i++) {
            if (signals & (ypollset_t::signals_t (1) << i)) {
                command_t cmd;
                while (dispatcher->read (i, get_thread_slot (), &cmd))
                    cmd.destination->process_command (cmd);
            }
        }
    }
}

zmq::socket_base_t *zmq::app_thread_t::create_socket (int type_)
{
    //  TODO: type is ignored for the time being.
    socket_base_t *s = new socket_base_t (this);
    zmq_assert (s);
    sockets.push_back (s);
    return s;
}

void zmq::app_thread_t::remove_socket (socket_base_t *socket_)
{
    //  TODO: To speed this up we can possibly use the system where each socket
    //        holds its index (see I/O scheduler implementation).
    sockets_t::iterator it = std::find (sockets.begin (), sockets.end (),
        socket_);
    zmq_assert (it != sockets.end ());
    sockets.erase (it);
}
