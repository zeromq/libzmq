 /*
    Copyright (c) 2007-2016 Contributors as noted in the AUTHORS file

    This file is part of libzmq, the ZeroMQ core engine in C++.

    libzmq is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License (LGPL) as published
    by the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    As a special exception, the Contributors give you permission to link
    this library with independent modules to produce an executable,
    regardless of the license terms of these independent modules, and to
    copy and distribute the resulting executable under terms of your choice,
    provided that you also meet, for each linked independent module, the
    terms and conditions of the license of that module. An independent
    module is a module which is not derived from or based on this library.
    If you modify this library, you must extend this exception to your
    version of the library.

    libzmq is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
    FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
    License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "precompiled.hpp"

#include "tipc_listener.hpp"

#if defined ZMQ_HAVE_TIPC

#include <new>

#include <string.h>

#include "stream_engine.hpp"
#include "tipc_address.hpp"
#include "io_thread.hpp"
#include "session_base.hpp"
#include "config.hpp"
#include "err.hpp"
#include "ip.hpp"
#include "socket_base.hpp"

#include <unistd.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <linux/tipc.h>

zmq::tipc_listener_t::tipc_listener_t (io_thread_t *io_thread_,
      socket_base_t *socket_, const options_t &options_) :
    own_t (io_thread_, options_),
    io_object_t (io_thread_),
    s (retired_fd),
    socket (socket_)
{
}

zmq::tipc_listener_t::~tipc_listener_t ()
{
    zmq_assert (s == retired_fd);
}

void zmq::tipc_listener_t::process_plug ()
{
    //  Start polling for incoming connections.
    handle = add_fd (s);
    set_pollin (handle);
}

void zmq::tipc_listener_t::process_term (int linger_)
{
    rm_fd (handle);
    close ();
    own_t::process_term (linger_);
}

void zmq::tipc_listener_t::in_event ()
{
    fd_t fd = accept ();

    //  If connection was reset by the peer in the meantime, just ignore it.
    //  TODO: Handle specific errors like ENFILE/EMFILE etc.
    if (fd == retired_fd) {
        socket->event_accept_failed (endpoint, zmq_errno());
        return;
    }

    //  Create the engine object for this connection.
    stream_engine_t *engine = new (std::nothrow) stream_engine_t (fd, options, endpoint);
    alloc_assert (engine);

    //  Choose I/O thread to run connecter in. Given that we are already
    //  running in an I/O thread, there must be at least one available.
    io_thread_t *io_thread = choose_io_thread (options.affinity);
    zmq_assert (io_thread);

    //  Create and launch a session object.
    session_base_t *session = session_base_t::create (io_thread, false, socket,
        options, NULL);
    errno_assert (session);
    session->inc_seqnum ();
    launch_child (session);
    send_attach (session, engine, false);
    socket->event_accepted (endpoint, fd);
}

int zmq::tipc_listener_t::get_address (std::string &addr_)
{
    struct sockaddr_storage ss;
    socklen_t sl = sizeof (ss);

    int rc = getsockname (s, (sockaddr *) &ss, &sl);
    if (rc != 0) {
        addr_.clear ();
        return rc;
    }

    tipc_address_t addr ((struct sockaddr *) &ss, sl);
    return addr.to_string (addr_);
}

int zmq::tipc_listener_t::set_address (const char *addr_)
{
    //convert str to address struct
    int rc = address.resolve(addr_);
    if (rc != 0)
        return -1;
    //  Create a listening socket.
    s = open_socket (AF_TIPC, SOCK_STREAM, 0);
    if (s == -1)
        return -1;

    address.to_string (endpoint);

    //  Bind the socket to tipc name.
    rc = bind (s, address.addr (), address.addrlen ());
    if (rc != 0)
        goto error;

    //  Listen for incoming connections.
    rc = listen (s, options.backlog);
    if (rc != 0)
        goto error;

    socket->event_listening (endpoint, s);
    return 0;

error:
    int err = errno;
    close ();
    errno = err;
    return -1;
}

void zmq::tipc_listener_t::close ()
{
    zmq_assert (s != retired_fd);
    int rc = ::close (s);
    errno_assert (rc == 0);
    s = retired_fd;
    socket->event_closed (endpoint, s);
}

zmq::fd_t zmq::tipc_listener_t::accept ()
{
    //  Accept one connection and deal with different failure modes.
    //  The situation where connection cannot be accepted due to insufficient
    //  resources is considered valid and treated by ignoring the connection.
    struct sockaddr_storage ss = {};
    socklen_t ss_len = sizeof(ss);

    zmq_assert (s != retired_fd);
    fd_t sock = ::accept (s, (struct sockaddr *) &ss, &ss_len);
    if (sock == -1) {
        errno_assert (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS ||
            errno == EINTR || errno == ECONNABORTED || errno == EPROTO || errno == EMFILE ||
            errno == ENFILE);
        return retired_fd;
    }
    /*FIXME Accept filters?*/
    return sock;
}

#endif

