/* SPDX-License-Identifier: MPL-2.0 */

#include "precompiled.hpp"

#include "vsock_connecter.hpp"
#include "vsock_address.hpp"

#if defined ZMQ_HAVE_VSOCK

#include <new>

#include "io_thread.hpp"
#include "platform.hpp"
#include "random.hpp"
#include "err.hpp"
#include "ip.hpp"
#include "address.hpp"
#include "session_base.hpp"
#include "sys/socket.h"
#include "linux/vm_sockets.h"

zmq::vsock_connecter_t::vsock_connecter_t (class io_thread_t *io_thread_,
                                           class session_base_t *session_,
                                           const options_t &options_,
                                           address_t *addr_,
                                           bool delayed_start_) :
    stream_connecter_base_t (
      io_thread_, session_, options_, addr_, delayed_start_),
    _connect_timer_started (false)
{
    zmq_assert (_addr->protocol == protocol_name::vsock);
}

zmq::vsock_connecter_t::~vsock_connecter_t ()
{
    zmq_assert (!_connect_timer_started);
}

void zmq::vsock_connecter_t::process_term (int linger_)
{
    if (_connect_timer_started) {
        cancel_timer (connect_timer_id);
        _connect_timer_started = false;
    }

    stream_connecter_base_t::process_term (linger_);
}

void zmq::vsock_connecter_t::in_event ()
{
    //  We are not polling for incoming data, so we are actually called
    //  because of error here. However, we can get error on out event as well
    //  on some platforms, so we'll simply handle both events in the same way.
    out_event ();
}

void zmq::vsock_connecter_t::out_event ()
{
    if (_connect_timer_started) {
        cancel_timer (connect_timer_id);
        _connect_timer_started = false;
    }

    //  TODO this is still very similar to (t)ipc_connecter_t, maybe the
    //  differences can be factored out

    rm_handle ();

    const fd_t fd = connect ();

    if (fd == retired_fd
        && ((options.reconnect_stop & ZMQ_RECONNECT_STOP_CONN_REFUSED)
            && errno == ECONNREFUSED)) {
        send_conn_failed (_session);
        close ();
        terminate ();
        return;
    }

    //  Handle the error condition by attempt to reconnect.
    if (fd == retired_fd) {
        close ();
        add_reconnect_timer ();
        return;
    }

    create_engine (
      fd, zmq::vsock_connecter_t::get_socket_name (fd, socket_end_local));
}

std::string
zmq::vsock_connecter_t::get_socket_name (zmq::fd_t fd_,
                                         socket_end_t socket_end_) const
{
    struct sockaddr_storage ss;
    const zmq_socklen_t sl = get_socket_address (fd_, socket_end_, &ss);
    if (sl == 0) {
        return std::string ();
    }

    const vsock_address_t addr (reinterpret_cast<struct sockaddr *> (&ss), sl,
                                this->get_ctx ());
    std::string address_string;
    addr.to_string (address_string);
    return address_string;
}

void zmq::vsock_connecter_t::timer_event (int id_)
{
    if (id_ == connect_timer_id) {
        _connect_timer_started = false;
        rm_handle ();
        close ();
        add_reconnect_timer ();
    } else
        stream_connecter_base_t::timer_event (id_);
}

void zmq::vsock_connecter_t::start_connecting ()
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

        //  add userspace connect timeout
        add_connect_timer ();
    }

    //  Handle any other error condition by eventual reconnect.
    else {
        if (_s != retired_fd)
            close ();
        add_reconnect_timer ();
    }
}

void zmq::vsock_connecter_t::add_connect_timer ()
{
    if (options.connect_timeout > 0) {
        add_timer (options.connect_timeout, connect_timer_id);
        _connect_timer_started = true;
    }
}

int zmq::vsock_connecter_t::open ()
{
    zmq_assert (_s == retired_fd);

    //  Resolve the address
    if (_addr->resolved.vsock_addr != NULL) {
        LIBZMQ_DELETE (_addr->resolved.vsock_addr);
    }

    _addr->resolved.vsock_addr =
      new (std::nothrow) vsock_address_t (this->get_ctx ());
    alloc_assert (_addr->resolved.vsock_addr);

    //  Convert the textual address into address structure.
    _addr->resolved.vsock_addr->resolve (_addr->address.c_str ());

    //  Create the socket.
    _s = open_socket (AF_VSOCK, SOCK_STREAM, 0);

    if (_s == retired_fd) {
        //  TODO we should emit some event in this case!

        LIBZMQ_DELETE (_addr->resolved.vsock_addr);
        return -1;
    }

    zmq_assert (_addr->resolved.vsock_addr != NULL);

    // Set the socket to non-blocking mode so that we get async connect().
    unblock_socket (_s);

    const vsock_address_t *const vsock_addr = _addr->resolved.vsock_addr;

    //  Connect to the remote peer.
    int rc = ::connect (_s, vsock_addr->addr (), vsock_addr->addrlen ());
    //  Connect was successful immediately.
    if (rc == 0) {
        return 0;
    }

    if (errno == EINTR)
        errno = EINPROGRESS;

    return -1;
}

zmq::fd_t zmq::vsock_connecter_t::connect ()
{
    //  Async connect has finished. Check whether an error occurred
    int err = 0;
    socklen_t len = sizeof err;

    const int rc = getsockopt (_s, SOL_SOCKET, SO_ERROR,
                               reinterpret_cast<char *> (&err), &len);

    //  Assert if the error was caused by 0MQ bug.
    //  Networking problems are OK. No need to assert.
    //  Following code should handle both Berkeley-derived socket
    //  implementations and Solaris.
    if (rc == -1)
        err = errno;
    if (err != 0) {
        errno = err;
        errno_assert (errno != ENOPROTOOPT && errno != ENOTSOCK
                      && errno != ENOBUFS);
        return retired_fd;
    }

    //  Return the newly connected socket.
    const fd_t result = _s;
    _s = retired_fd;
    return result;
}

#endif
