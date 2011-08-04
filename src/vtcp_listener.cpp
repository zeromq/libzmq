/*
    Copyright (c) 2007-2011 iMatix Corporation
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

#include "vtcp_listener.hpp"

#if defined ZMQ_HAVE_VTCP

#include <string>
#include <string.h>
#include <vtcp.h>

#include "tcp_engine.hpp"
#include "session.hpp"
#include "stdint.hpp"
#include "err.hpp"
#include "ip.hpp"

zmq::vtcp_listener_t::vtcp_listener_t (io_thread_t *io_thread_,
        socket_base_t *socket_, options_t &options_) :
    own_t (io_thread_, options_),
    io_object_t (io_thread_),
    s (retired_fd),
    socket (socket_)
{
}

zmq::vtcp_listener_t::~vtcp_listener_t ()
{
    zmq_assert (s != retired_fd);
    int rc = ::close (s);
    errno_assert (rc == 0);
    s = retired_fd;
}

int zmq::vtcp_listener_t::set_address (const char *addr_)
{
    //  VTCP doesn't allow for binding to a specific interface. Connection
    //  string has to begin with *: (INADDR_ANY).
    if (strlen (addr_) < 2 || addr_ [0] != '*' || addr_ [1] != ':') {
        errno = EADDRNOTAVAIL;
        return -1;
    }

    //  Parse port and subport.
    uint16_t port;
    uint32_t subport;
    const char *delimiter = strrchr (addr_, '.');
    if (!delimiter) {
        port = 9220;
        subport = (uint32_t) atoi (addr_ + 2);
    }
    else {
        std::string port_str (addr_ + 2, delimiter - addr_ - 2);
        std::string subport_str (delimiter + 1);
        port = (uint16_t) atoi (port_str.c_str ());
        subport = (uint32_t) atoi (subport_str.c_str ());
    }

    //  Start listening.
    s = vtcp_bind (port, subport);
    if (s == retired_fd)
        return -1;

    return 0;
}

void zmq::vtcp_listener_t::process_plug ()
{
    //  Start polling for incoming connections.
    handle = add_fd (s);
    set_pollin (handle);
}

void zmq::vtcp_listener_t::process_term (int linger_)
{
    rm_fd (handle);
    own_t::process_term (linger_);
}

void zmq::vtcp_listener_t::in_event ()
{
    fd_t fd = vtcp_acceptb (s);
    if (fd == retired_fd)
        return;

    tune_tcp_socket (fd);

    //  Create the engine object for this connection.
    tcp_engine_t *engine = new (std::nothrow) tcp_engine_t (fd, options);
    alloc_assert (engine);

    //  Choose I/O thread to run connecter in. Given that we are already
    //  running in an I/O thread, there must be at least one available.
    io_thread_t *io_thread = choose_io_thread (options.affinity);
    zmq_assert (io_thread);

    //  Create and launch a session object. 
    session_t *session = new (std::nothrow)
        session_t (io_thread, false, socket, options, NULL, NULL);
    alloc_assert (session);
    session->inc_seqnum ();
    launch_child (session);
    send_attach (session, engine, false);
}

#endif
