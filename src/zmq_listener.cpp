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

#include "zmq_listener.hpp"
#include "zmq_engine.hpp"
#include "io_thread.hpp"
#include "err.hpp"

zmq::zmq_listener_t::zmq_listener_t (io_thread_t *parent_, object_t *owner_) :
    io_object_t (parent_, owner_)
{
}

zmq::zmq_listener_t::~zmq_listener_t ()
{
    if (plugged_in)
        rm_fd (handle);
}

int zmq::zmq_listener_t::set_address (const char *addr_)
{
     return tcp_listener.set_address (addr_);
}

void zmq::zmq_listener_t::process_plug ()
{
    //  Open the listening socket.
    int rc = tcp_listener.open ();
    zmq_assert (rc == 0);

    //  Start polling for incoming connections.
    handle = add_fd (tcp_listener.get_fd (), this);
    set_pollin (handle);

    io_object_t::process_plug ();
}

void zmq::zmq_listener_t::in_event ()
{
    fd_t fd = tcp_listener.accept ();

    //  If connection was reset by the peer in the meantime, just ignore it.
    //  TODO: Handle specific errors like ENFILE/EMFILE etc.
    if (fd == retired_fd)
        return;

    //  TODO
    zmq_assert (false);

/*
    object_t *engine = new zmq_engine_t (choose_io_thread (0), owner);
    send_plug (engine);
    send_own (owner, engine);
*/
}



