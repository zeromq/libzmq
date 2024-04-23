/* SPDX-License-Identifier: MPL-2.0 */

#include "precompiled.hpp"
#include "ipc_connecter.hpp"

#if defined ZMQ_HAVE_IPC

#include <new>
#include <string>

#include "io_thread.hpp"
#include "random.hpp"
#include "err.hpp"
#include "ip.hpp"
#include "address.hpp"
#include "ipc_address.hpp"
#include "session_base.hpp"

#if defined ZMQ_HAVE_WINDOWS
#include <afunix.h>
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#endif

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
    const fd_t fd = connect ();
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
    const int rc = open ();

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
    //stop connecting after called zmq_disconnect
    else if (rc == -1
             && (options.reconnect_stop & ZMQ_RECONNECT_STOP_AFTER_DISCONNECT)
             && errno == ECONNREFUSED && _socket->is_disconnected ()) {
        if (_s != retired_fd)
            close ();
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
    if (_s == retired_fd)
        return -1;

    //  Set the non-blocking flag.
    unblock_socket (_s);

    //  Connect to the remote peer.
    const int rc = ::connect (_s, _addr->resolved.ipc_addr->addr (),
                              _addr->resolved.ipc_addr->addrlen ());

    //  Connect was successful immediately.
    if (rc == 0)
        return 0;

        //  Translate other error codes indicating asynchronous connect has been
        //  launched to a uniform EINPROGRESS.
#ifdef ZMQ_HAVE_WINDOWS
    const int last_error = WSAGetLastError ();
    if (last_error == WSAEINPROGRESS || last_error == WSAEWOULDBLOCK)
        errno = EINPROGRESS;
    else
        errno = wsa_error_to_errno (last_error);
#else
    if (rc == -1 && errno == EINTR) {
        errno = EINPROGRESS;
    }
#endif

    //  Forward the error.
    return -1;
}

zmq::fd_t zmq::ipc_connecter_t::connect ()
{
    //  Following code should handle both Berkeley-derived socket
    //  implementations and Solaris.
    int err = 0;
    zmq_socklen_t len = static_cast<zmq_socklen_t> (sizeof (err));
    const int rc = getsockopt (_s, SOL_SOCKET, SO_ERROR,
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

    const fd_t result = _s;
    _s = retired_fd;
    return result;
}

#endif
