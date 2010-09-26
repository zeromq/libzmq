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

#include <new>
#include <algorithm>

#include "../include/zmq.h"

#include "platform.hpp"

#if defined ZMQ_HAVE_WINDOWS
#include "windows.hpp"
#if defined _MSC_VER
#include <intrin.h>
#endif
#else
#include <unistd.h>
#endif

#include "app_thread.hpp"
#include "ctx.hpp"
#include "err.hpp"
#include "pipe.hpp"
#include "config.hpp"
#include "socket_base.hpp"
#include "pair.hpp"
#include "pub.hpp"
#include "sub.hpp"
#include "req.hpp"
#include "rep.hpp"
#include "xreq.hpp"
#include "xrep.hpp"
#include "pull.hpp"
#include "push.hpp"

//  If the RDTSC is available we use it to prevent excessive
//  polling for commands. The nice thing here is that it will work on any
//  system with x86 architecture and gcc or MSVC compiler.
#if (defined __GNUC__ && (defined __i386__ || defined __x86_64__)) ||\
    (defined _MSC_VER && (defined _M_IX86 || defined _M_X64))
#define ZMQ_DELAY_COMMANDS
#endif

zmq::app_thread_t::app_thread_t (ctx_t *ctx_,
        uint32_t thread_slot_) :
    object_t (ctx_, thread_slot_),
    last_processing_time (0),
    terminated (false)
{
}

zmq::app_thread_t::~app_thread_t ()
{
    zmq_assert (sockets.empty ());
}

void zmq::app_thread_t::stop ()
{
    send_stop ();
}

zmq::signaler_t *zmq::app_thread_t::get_signaler ()
{
    return &signaler;
}

bool zmq::app_thread_t::process_commands (bool block_, bool throttle_)
{
    bool received;
    command_t cmd;
    if (block_) {
        received = signaler.recv (&cmd, true);
        zmq_assert (received);
    }   
    else {

#if defined ZMQ_DELAY_COMMANDS
        //  Optimised version of command processing - it doesn't have to check
        //  for incoming commands each time. It does so only if certain time
        //  elapsed since last command processing. Command delay varies
        //  depending on CPU speed: It's ~1ms on 3GHz CPU, ~2ms on 1.5GHz CPU
        //  etc. The optimisation makes sense only on platforms where getting
        //  a timestamp is a very cheap operation (tens of nanoseconds).
        if (throttle_) {

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

            //  Check whether TSC haven't jumped backwards (in case of migration
            //  between CPU cores) and whether certain time have elapsed since
            //  last command processing. If it didn't do nothing.
            if (current_time >= last_processing_time &&
                  current_time - last_processing_time <= max_command_delay)
                return !terminated;
            last_processing_time = current_time;
        }
#endif

        //  Check whether there are any commands pending for this thread.
        received = signaler.recv (&cmd, false);
    }

    //  Process all the commands available at the moment.
    while (received) {
        cmd.destination->process_command (cmd);
        received = signaler.recv (&cmd, false);
    }

    return !terminated;
}

zmq::socket_base_t *zmq::app_thread_t::create_socket (int type_)
{
    socket_base_t *s = NULL;
    switch (type_) {
    case ZMQ_PAIR:
        s = new (std::nothrow) pair_t (this);
        break;
    case ZMQ_PUB:
        s = new (std::nothrow) pub_t (this);
        break;
    case ZMQ_SUB:
        s = new (std::nothrow) sub_t (this);
        break;
    case ZMQ_REQ:
        s = new (std::nothrow) req_t (this);
        break;
    case ZMQ_REP:
        s = new (std::nothrow) rep_t (this);
        break;
    case ZMQ_XREQ:
        s = new (std::nothrow) xreq_t (this);
        break;
    case ZMQ_XREP:
        s = new (std::nothrow) xrep_t (this);
        break;       
    case ZMQ_PULL:
        s = new (std::nothrow) pull_t (this);
        break;
    case ZMQ_PUSH:
        s = new (std::nothrow) push_t (this);
        break;
    default:
        if (sockets.empty ())
            get_ctx ()->no_sockets (this);
        errno = EINVAL;
        return NULL;
    }
    zmq_assert (s);

    sockets.push_back (s);

    return s;
}

void zmq::app_thread_t::remove_socket (socket_base_t *socket_)
{
    sockets.erase (socket_);
    if (sockets.empty ())
        get_ctx ()->no_sockets (this);
}

void zmq::app_thread_t::process_stop ()
{
    terminated = true;
}

bool zmq::app_thread_t::is_terminated ()
{
    return terminated;
}

