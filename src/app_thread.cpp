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

#include "../include/zmq.h"

#if defined ZMQ_HAVE_WINDOWS
#include "windows.hpp"
#else
#include <unistd.h>
#endif

#include "app_thread.hpp"
#include "dispatcher.hpp"
#include "err.hpp"
#include "session.hpp"
#include "pipe.hpp"
#include "config.hpp"
#include "i_api.hpp"
#include "dummy_aggregator.hpp"
#include "fair_aggregator.hpp"
#include "dummy_distributor.hpp"
#include "data_distributor.hpp"
#include "load_balancer.hpp"
#include "p2p.hpp"
#include "pub.hpp"
#include "sub.hpp"
#include "req.hpp"
#include "rep.hpp"

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

void zmq::app_thread_t::shutdown ()
{
    //  Deallocate all the sessions associated with the thread.
    while (!sessions.empty ())
        sessions [0]->shutdown ();

    delete this;
}

zmq::app_thread_t::~app_thread_t ()
{
}

void zmq::app_thread_t::attach_session (session_t *session_)
{
    session_->set_index (sessions.size ());
    sessions.push_back (session_); 
}

void zmq::app_thread_t::detach_session (session_t *session_)
{
    //  O(1) removal of the session from the list.
    sessions_t::size_type i = session_->get_index ();
    sessions [i] = sessions [sessions.size () - 1];
    sessions [i]->set_index (i);
    sessions.pop_back ();
}

zmq::i_poller *zmq::app_thread_t::get_poller ()
{
    zmq_assert (false);
}

zmq::i_signaler *zmq::app_thread_t::get_signaler ()
{
    return &pollset;
}

bool zmq::app_thread_t::is_current ()
{
    return !sessions.empty () && tid == getpid ();
}

bool zmq::app_thread_t::make_current ()
{
    //  If there are object managed by this slot we cannot assign the slot
    //  to a different thread.
    if (!sessions.empty ())
        return false;

    tid = getpid ();
    return true;
}

zmq::i_api *zmq::app_thread_t::create_socket (int type_)
{
    i_mux *mux = NULL;
    i_demux *demux = NULL;
    session_t *session = NULL;
    i_api *api = NULL;

    switch (type_) {
    case ZMQ_P2P:
        mux = new dummy_aggregator_t;
        zmq_assert (mux);
        demux = new dummy_distributor_t;
        zmq_assert (demux);
        session = new session_t (this, this, mux, demux, true, false);
        zmq_assert (session);
        api = new p2p_t (this, session);
        zmq_assert (api);
        break;
    case ZMQ_PUB:
        demux = new data_distributor_t;
        zmq_assert (demux);
        session = new session_t (this, this, mux, demux, true, false);
        zmq_assert (session);
        api = new pub_t (this, session);
        zmq_assert (api);
        break;
    case ZMQ_SUB:
        mux = new fair_aggregator_t;
        zmq_assert (mux);
        session = new session_t (this, this, mux, demux, true, false);
        zmq_assert (session);
        api = new sub_t (this, session);
        zmq_assert (api);
        break;
    case ZMQ_REQ:
        //  TODO
        zmq_assert (false);
        api = new req_t (this, session);
        zmq_assert (api);
        break;
    case ZMQ_REP:
        //  TODO
        zmq_assert (false);
        api = new rep_t (this, session);
        zmq_assert (api);
        break;
    default:
        errno = EINVAL;
        return NULL;
    }

    attach_session (session);
    
    return api;
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
