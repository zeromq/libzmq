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

#include "socket_base.hpp"
#include "app_thread.hpp"
#include "err.hpp"
#include "zmq_listener.hpp"
#include "io_thread.hpp"

zmq::socket_base_t::socket_base_t (app_thread_t *parent_) :
    object_t (parent_),
    pending_term_acks (0),
    app_thread (parent_)
{
}

zmq::socket_base_t::~socket_base_t ()
{
    while (true) {

        //  On third pass of the loop there should be no more I/O objects
        //  because all connecters and listerners were destroyed during
        //  the first pass and all engines delivered by delayed 'own' commands
        //  are destroyed during the second pass.
        if (io_objects.empty () && !pending_term_acks)
            break;

        //  Send termination request to all associated I/O objects.
        for (io_objects_t::iterator it = io_objects.begin ();
              it != io_objects.end (); it++)
            send_term (*it);

        //  Move the objects to the list of pending term acks.
        pending_term_acks += io_objects.size ();
        io_objects.clear ();

        //  Process commands till we get all the termination acknowledgements.
        while (pending_term_acks)
            app_thread->process_commands (true);
    }
}

int zmq::socket_base_t::setsockopt (int option_, void *optval_,
    size_t optvallen_)
{
    zmq_assert (false);
}

int zmq::socket_base_t::bind (const char *addr_)
{
    //  TODO: The taskset should be taken from socket options.
    uint64_t taskset = 0;
    zmq_listener_t *listener = new zmq_listener_t (choose_io_thread (taskset), this);
    int rc = listener->set_address (addr_);
    if (rc != 0)
        return -1;

    send_plug (listener);
    send_own (this, listener);
    return 0;
}

int zmq::socket_base_t::connect (const char *addr_)
{
    zmq_assert (false);
}

int zmq::socket_base_t::subscribe (const char *criteria_)
{
    zmq_assert (false);
}

int zmq::socket_base_t::send (struct zmq_msg *msg_, int flags_)
{
    zmq_assert (false);
}

int zmq::socket_base_t::flush ()
{
    zmq_assert (false);
}

int zmq::socket_base_t::recv (struct zmq_msg *msg_, int flags_)
{
    zmq_assert (false);
}

int zmq::socket_base_t::close ()
{
    app_thread->remove_socket (this);
    delete this;
    return 0;
}

void zmq::socket_base_t::process_own (object_t *object_)
{
    io_objects.insert (object_);
}

void zmq::socket_base_t::process_term_req (object_t *object_)
{
    //  If I/O object is well and alive ask it to terminate.
    io_objects_t::iterator it = std::find (io_objects.begin (),
        io_objects.end (), object_);

    //  If not found, we assume that termination request was already sent to
    //  the object so we can sagely ignore the request.
    if (it == io_objects.end ())
        return;

    pending_term_acks++;
    io_objects.erase (it);
    send_term (object_);
}

void zmq::socket_base_t::process_term_ack ()
{
    zmq_assert (pending_term_acks);
    pending_term_acks--;
}
