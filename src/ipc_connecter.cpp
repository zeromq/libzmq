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

#if defined ZMQ_HAVE_LINUX
#include "shm_engine.hpp"
#include "shm_fd.hpp"
#include "socket_base.hpp"
#include <sys/mman.h>
#include <sys/stat.h>
#endif

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
                                       bool delayed_start_,
                                       bool use_shm_) :
    stream_connecter_base_t (
      io_thread_, session_, options_, addr_, delayed_start_),
    _use_shm (use_shm_),
    _waiting_for_shm_fd (false),
    _shm_handshake_timer_started (false)
{
#if defined ZMQ_HAVE_LINUX
    zmq_assert (_addr->protocol == protocol_name::ipc
                || _addr->protocol == protocol_name::shm);
#else
    zmq_assert (_addr->protocol == protocol_name::ipc);
    zmq_assert (!_use_shm);
#endif
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

    std::string local_address =
      get_socket_name<ipc_address_t> (fd, socket_end_local);
#if defined ZMQ_HAVE_LINUX
    if (_use_shm) {
        _s = fd;
        _handle = add_fd (_s);
        set_pollin (_handle);
        _waiting_for_shm_fd = true;
        if (options.handshake_ivl > 0) {
            add_timer (options.handshake_ivl, shm_handshake_timer_id);
            _shm_handshake_timer_started = true;
        }
        return;
    }
#endif
    create_engine (fd, local_address);
}

#if defined ZMQ_HAVE_LINUX
void zmq::ipc_connecter_t::in_event ()
{
    if (!_waiting_for_shm_fd) {
        out_event ();
        return;
    }
    receive_shm_engine ();
}

void zmq::ipc_connecter_t::fail_shm_handshake ()
{
    if (_shm_handshake_timer_started) {
        cancel_timer (shm_handshake_timer_id);
        _shm_handshake_timer_started = false;
    }
    _waiting_for_shm_fd = false;
    rm_handle ();
    close ();
    add_reconnect_timer ();
}

void zmq::ipc_connecter_t::receive_shm_engine ()
{
    zmq_assert (_waiting_for_shm_fd);

    int fds[3];
    if (shm_recv_fds (_s, fds) != 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK)
            fail_shm_handshake ();
        return;
    }

    const size_t expected_size = shm_engine_t::mapping_size ();
    struct stat stat_buf;
    if (fstat (fds[0], &stat_buf) != 0
        || stat_buf.st_size != static_cast<off_t> (expected_size)) {
        ::close (fds[0]);
        ::close (fds[1]);
        ::close (fds[2]);
        errno = EPROTO;
        fail_shm_handshake ();
        return;
    }

    void *const mapping = shm_map_fd (fds[0], expected_size);
    const int saved_errno = errno;
    ::close (fds[0]);
    errno = saved_errno;
    if (mapping == MAP_FAILED) {
        ::close (fds[1]);
        ::close (fds[2]);
        fail_shm_handshake ();
        return;
    }

    bool valid = false;
    {
        shm_channel_t channel (mapping, expected_size, false);
        valid = channel.valid ();
    }
    if (!valid) {
        munmap (mapping, expected_size);
        ::close (fds[1]);
        ::close (fds[2]);
        errno = EPROTO;
        fail_shm_handshake ();
        return;
    }

    std::string local_address =
      get_socket_name<ipc_address_t> (_s, socket_end_local);
    if (local_address.compare (0, 6, "ipc://") == 0)
        local_address.replace (0, 6, "shm://");

    const fd_t fd = _s;
    _s = retired_fd;
    _waiting_for_shm_fd = false;
    if (_shm_handshake_timer_started) {
        cancel_timer (shm_handshake_timer_id);
        _shm_handshake_timer_started = false;
    }
    rm_handle ();

    const endpoint_uri_pair_t endpoint_pair (local_address, _endpoint,
                                             endpoint_type_connect);
    shm_state_t *const state = shm_state_t::create (
      mapping, expected_size, false, fd, fds[1]);
    if (!state) {
        const int state_errno = errno;
        ::close (fds[2]);
        ::close (fd);
        errno = state_errno;
        add_reconnect_timer ();
        return;
    }
    shm_engine_t *const engine = new (std::nothrow)
      shm_engine_t (fd, fds[2], state, endpoint_pair);
    alloc_assert (engine);
    zmq_assert (engine->valid ());

    send_attach (_session, engine);
    terminate ();
    _socket->event_connected (endpoint_pair, fd);
}
#else
void zmq::ipc_connecter_t::in_event ()
{
    out_event ();
}
#endif

void zmq::ipc_connecter_t::timer_event (int id_)
{
#if defined ZMQ_HAVE_LINUX
    if (id_ == shm_handshake_timer_id) {
        zmq_assert (_shm_handshake_timer_started);
        _shm_handshake_timer_started = false;
        fail_shm_handshake ();
        return;
    }
#endif
    stream_connecter_base_t::timer_event (id_);
}

void zmq::ipc_connecter_t::process_term (int linger_)
{
    if (_shm_handshake_timer_started) {
        cancel_timer (shm_handshake_timer_id);
        _shm_handshake_timer_started = false;
    }
    stream_connecter_base_t::process_term (linger_);
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
