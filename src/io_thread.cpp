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

#include "../include/zmq.h"

#include "io_thread.hpp"
#include "command.hpp"
#include "platform.hpp"
#include "err.hpp"
#include "command.hpp"
#include "dispatcher.hpp"

zmq::io_thread_t::io_thread_t (dispatcher_t *dispatcher_,
      uint32_t thread_slot_) :
    object_t (dispatcher_, thread_slot_)
{
    poller = new (std::nothrow) poller_t;
    zmq_assert (poller);

    signaler_handle = poller->add_fd (signaler.get_fd (), this);
    poller->set_pollin (signaler_handle);
}

zmq::io_thread_t::~io_thread_t ()
{
    delete poller;
}

void zmq::io_thread_t::start ()
{
    //  Start the underlying I/O thread.
    poller->start ();
}

void zmq::io_thread_t::stop ()
{
    send_stop ();
}

zmq::signaler_t *zmq::io_thread_t::get_signaler ()
{
    return &signaler;
}

int zmq::io_thread_t::get_load ()
{
    return poller->get_load ();
}

void zmq::io_thread_t::in_event ()
{
    while (true) {

        //  Get the next signal.
        uint32_t signal = signaler.check ();
        if (signal == signaler_t::no_signal)
            break;

        //  Process all the commands from the thread that sent the signal.
        command_t cmd;
        while (dispatcher->read (signal, thread_slot, &cmd))
            cmd.destination->process_command (cmd);
    }
}

void zmq::io_thread_t::out_event ()
{
    //  We are never polling for POLLOUT here. This function is never called.
    zmq_assert (false);
}

void zmq::io_thread_t::timer_event ()
{
    //  No timers here. This function is never called.
    zmq_assert (false);
}

zmq::poller_t *zmq::io_thread_t::get_poller ()
{
    zmq_assert (poller);
    return poller;
}

void zmq::io_thread_t::process_stop ()
{
    poller->rm_fd (signaler_handle);
    poller->stop ();
}
