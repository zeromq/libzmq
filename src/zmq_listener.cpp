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

#include "zmq_listener.hpp"
#include "zmq_init.hpp"
#include "io_thread.hpp"
#include "err.hpp"

zmq::zmq_listener_t::zmq_listener_t (io_thread_t *parent_,
      socket_base_t *owner_, const options_t &options_) :
    owned_t (parent_, owner_),
    io_object_t (parent_),
    options (options_)
{
}

zmq::zmq_listener_t::~zmq_listener_t ()
{
}

int zmq::zmq_listener_t::set_address (const char *protocol_, const char *addr_)
{
     return tcp_listener.set_address (protocol_, addr_);
}

void zmq::zmq_listener_t::process_plug ()
{
    //  Start polling for incoming connections.
    handle = add_fd (tcp_listener.get_fd ());
    set_pollin (handle);
}

void zmq::zmq_listener_t::process_unplug ()
{
    rm_fd (handle);
}

void zmq::zmq_listener_t::in_event ()
{
    fd_t fd = tcp_listener.accept ();

    //  If connection was reset by the peer in the meantime, just ignore it.
    //  TODO: Handle specific errors like ENFILE/EMFILE etc.
    if (fd == retired_fd)
        return;

    //  Create an init object. 
    io_thread_t *io_thread = choose_io_thread (options.affinity);
    zmq_init_t *init = new (std::nothrow) zmq_init_t (
        io_thread, owner, fd, options, false, NULL, NULL, 0);
    zmq_assert (init);
    send_plug (init);
    send_own (owner, init);
}



