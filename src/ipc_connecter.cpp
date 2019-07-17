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
#include "ipc_connecter.hpp"

#if !defined ZMQ_HAVE_WINDOWS && !defined ZMQ_HAVE_OPENVMS                     \
  && !defined ZMQ_HAVE_VXWORKS

#include <new>
#include <string>

#include "io_thread.hpp"
#include "random.hpp"
#include "err.hpp"
#include "ip.hpp"
#include "address.hpp"
#include "ipc_address.hpp"
#include "session_base.hpp"

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>


zmq::ipc_connecter_t::ipc_connecter_t (class io_thread_t *io_thread_,
                                       class session_base_t *session_,
                                       const options_t &options_,
                                       address_t *addr_,
                                       bool delayed_start_) :
    stream_connecter_base_t (
      io_thread_, session_, options_, addr_, delayed_start_)
{
    zmq_assert (_addr->protocol == protocol_name::ipc);
}

void zmq::ipc_connecter_t::out_event ()
{
    fd_t fd = connect ();
    rm_handle ();

    //  Handle the error condition by attempt to reconnect.
    if (fd == retired_fd) {
        close ();
        add_reconnect_timer ();
        return;
    }

    create_engine (fd, get_socket_name<ipc_address_t> (fd, socket_end_local));
}

void zmq::ipc_connecter_t::start_connecting ()
{
    //  Open the connecting socket.
    int rc = open ();

    //  Connect may succeed in synchronous manner.
    if (rc == 0) {
        _handle = add_fd (_s);
        out_event ();
    }

    //  Connection establishment may be delayed. Poll for its completion.
    else if (rc == -1 && errno == EINPROGRESS) {
        _handle = add_fd (_s);
        set_pollout (_handle);
        _socket->event_connect_delayed (
          make_unconnected_connect_endpoint_pair (_endpoint), zmq_errno ());

        // TODO, tcp_connecter_t adds a connect timer in this case; maybe this
        // should be done here as well (and then this could be pulled up to
        // stream_connecter_base_t).
    }

    //  Handle any other error condition by eventual reconnect.
    else {
        if (_s != retired_fd)
            close ();
        add_reconnect_timer ();
    }
}

int zmq::ipc_connecter_t::open ()
{
    zmq_assert (_s == retired_fd);

    //  Create the socket.
    _s = open_socket (AF_UNIX, SOCK_STREAM, 0);
    if (_s == -1)
        return -1;

    //  Set the non-blocking flag.
    unblock_socket (_s);

    //  Connect to the remote peer.
    int rc = ::connect (_s, _addr->resolved.ipc_addr->addr (),
                        _addr->resolved.ipc_addr->addrlen ());

    //  Connect was successful immediately.
    if (rc == 0)
        return 0;

    //  Translate other error codes indicating asynchronous connect has been
    //  launched to a uniform EINPROGRESS.
    if (rc == -1 && errno == EINTR) {
        errno = EINPROGRESS;
        return -1;
    }

    //  Forward the error.
    return -1;
}

zmq::fd_t zmq::ipc_connecter_t::connect ()
{
    //  Following code should handle both Berkeley-derived socket
    //  implementations and Solaris.
    int err = 0;
    zmq_socklen_t len = static_cast<zmq_socklen_t> (sizeof (err));
    int rc = getsockopt (_s, SOL_SOCKET, SO_ERROR,
                         reinterpret_cast<char *> (&err), &len);
    if (rc == -1) {
        if (errno == ENOPROTOOPT)
            errno = 0;
        err = errno;
    }
    if (err != 0) {
        //  Assert if the error was caused by 0MQ bug.
        //  Networking problems are OK. No need to assert.
        errno = err;
        errno_assert (errno == ECONNREFUSED || errno == ECONNRESET
                      || errno == ETIMEDOUT || errno == EHOSTUNREACH
                      || errno == ENETUNREACH || errno == ENETDOWN);

        return retired_fd;
    }

    fd_t result = _s;
    _s = retired_fd;
    return result;
}

#endif
