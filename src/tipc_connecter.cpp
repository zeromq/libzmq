/* SPDX-License-Identifier: MPL-2.0 */

#include "precompiled.hpp"

#include "tipc_connecter.hpp"

#if defined ZMQ_HAVE_TIPC

#include <new>
#include <string>

#include "io_thread.hpp"
#include "platform.hpp"
#include "random.hpp"
#include "err.hpp"
#include "ip.hpp"
#include "address.hpp"
#include "tipc_address.hpp"
#include "session_base.hpp"

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#ifdef ZMQ_HAVE_VXWORKS
#include <sockLib.h>
#endif

zmq::tipc_connecter_t::tipc_connecter_t (class io_thread_t *io_thread_,
                                         class session_base_t *session_,
                                         const options_t &options_,
                                         address_t *addr_,
                                         bool delayed_start_) :
    stream_connecter_base_t (
      io_thread_, session_, options_, addr_, delayed_start_)
{
    zmq_assert (_addr->protocol == "tipc");
}

void zmq::tipc_connecter_t::out_event ()
{
    fd_t fd = connect ();
    rm_handle ();

    //  Handle the error condition by attempt to reconnect.
    if (fd == retired_fd) {
        close ();
        add_reconnect_timer ();
        return;
    }

    create_engine (fd, get_socket_name<tipc_address_t> (fd, socket_end_local));
}

void zmq::tipc_connecter_t::start_connecting ()
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
    }

    //  Handle any other error condition by eventual reconnect.
    else {
        if (_s != retired_fd)
            close ();
        add_reconnect_timer ();
    }
}

int zmq::tipc_connecter_t::open ()
{
    zmq_assert (_s == retired_fd);

    // Cannot connect to random tipc addresses
    if (_addr->resolved.tipc_addr->is_random ()) {
        errno = EINVAL;
        return -1;
    }
    //  Create the socket.
    _s = open_socket (AF_TIPC, SOCK_STREAM, 0);
    if (_s == retired_fd)
        return -1;

    //  Set the non-blocking flag.
    unblock_socket (_s);
    //  Connect to the remote peer.
#ifdef ZMQ_HAVE_VXWORKS
    int rc = ::connect (s, (sockaddr *) addr->resolved.tipc_addr->addr (),
                        addr->resolved.tipc_addr->addrlen ());
#else
    int rc = ::connect (_s, _addr->resolved.tipc_addr->addr (),
                        _addr->resolved.tipc_addr->addrlen ());
#endif
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

zmq::fd_t zmq::tipc_connecter_t::connect ()
{
    //  Following code should handle both Berkeley-derived socket
    //  implementations and Solaris.
    int err = 0;
#ifdef ZMQ_HAVE_VXWORKS
    int len = sizeof (err);
#else
    socklen_t len = sizeof (err);
#endif
    int rc = getsockopt (_s, SOL_SOCKET, SO_ERROR,
                         reinterpret_cast<char *> (&err), &len);
    if (rc == -1)
        err = errno;
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
