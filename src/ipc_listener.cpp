/*
    Copyright (c) 2011 250bpm s.r.o.
    Copyright (c) 2011 Other contributors as noted in the AUTHORS file

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

#include "ipc_listener.hpp"

#if !defined ZMQ_HAVE_WINDOWS && !defined ZMQ_HAVE_OPENVMS

#include <new>

#include <string.h>

#include "stream_engine.hpp"
#include "ipc_address.hpp"
#include "io_thread.hpp"
#include "session_base.hpp"
#include "config.hpp"
#include "err.hpp"
#include "ip.hpp"

#include <unistd.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/un.h>

zmq::ipc_listener_t::ipc_listener_t (io_thread_t *io_thread_,
      socket_base_t *socket_, const options_t &options_) :
    own_t (io_thread_, options_),
    io_object_t (io_thread_),
    has_file (false),
    s (retired_fd),
    socket (socket_)
{
}

zmq::ipc_listener_t::~ipc_listener_t ()
{
    if (s != retired_fd)
        close ();
}

void zmq::ipc_listener_t::process_plug ()
{
    //  Start polling for incoming connections.
    handle = add_fd (s);
    set_pollin (handle);
}

void zmq::ipc_listener_t::process_term (int linger_)
{
    rm_fd (handle);
    own_t::process_term (linger_);
}

void zmq::ipc_listener_t::in_event ()
{
    fd_t fd = accept ();

    //  If connection was reset by the peer in the meantime, just ignore it.
    //  TODO: Handle specific errors like ENFILE/EMFILE etc.
    if (fd == retired_fd)
        return;

    //  Create the engine object for this connection.
    stream_engine_t *engine = new (std::nothrow) stream_engine_t (fd, options);
    alloc_assert (engine);

    //  Choose I/O thread to run connecter in. Given that we are already
    //  running in an I/O thread, there must be at least one available.
    io_thread_t *io_thread = choose_io_thread (options.affinity);
    zmq_assert (io_thread);

    //  Create and launch a session object. 
    session_base_t *session = session_base_t::create (io_thread, false, socket,
        options, NULL, NULL);
    errno_assert (session);
    session->inc_seqnum ();
    launch_child (session);
    send_attach (session, engine, false);
}

int zmq::ipc_listener_t::set_address (const char *addr_)
{
    //  Get rid of the file associated with the UNIX domain socket that
    //  may have been left behind by the previous run of the application.
    ::unlink (addr_);
    filename.clear ();

    //  Initialise the address structure.
    ipc_address_t address;
    int rc = address.resolve (addr_);
    if (rc != 0)
        return -1;

    //  Create a listening socket.
    s = open_socket (AF_UNIX, SOCK_STREAM, 0);
    if (s == -1)
        return -1;

    //  Bind the socket to the file path.
    rc = bind (s, address.addr (), address.addrlen ());
    if (rc != 0)
        return -1;

    has_file = true;

    //  Listen for incomming connections.
    rc = listen (s, options.backlog);
    if (rc != 0)
        return -1;

    return 0;  
}

int zmq::ipc_listener_t::close ()
{
    zmq_assert (s != retired_fd);
    int rc = ::close (s);
    if (rc != 0)
        return -1;
    s = retired_fd;

    //  If there's an underlying UNIX domain socket, get rid of the file it
    //  is associated with.
    if (has_file && !filename.empty ()) {
        rc = ::unlink(filename.c_str ());
        if (rc != 0)
            return -1;
    }

    return 0;
}

zmq::fd_t zmq::ipc_listener_t::accept ()
{
    //  Accept one connection and deal with different failure modes.
    zmq_assert (s != retired_fd);
    fd_t sock = ::accept (s, NULL, NULL);
    if (sock == -1) {
        errno_assert (errno == EAGAIN || errno == EWOULDBLOCK ||
            errno == EINTR || errno == ECONNABORTED || errno == EPROTO ||
            errno == ENOBUFS);
        return retired_fd;
    }
    return sock;
}

#endif

