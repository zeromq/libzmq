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

#include "tipc_connecter.hpp"

#if defined ZMQ_HAVE_TIPC

#include <new>
#include <string>

#include "stream_engine.hpp"
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
                                         const address_t *addr_,
                                         bool delayed_start_) :
    own_t (io_thread_, options_),
    io_object_t (io_thread_),
    _addr (addr_),
    _s (retired_fd),
    _handle_valid (false),
    _delayed_start (delayed_start_),
    _timer_started (false),
    _session (session_),
    _current_reconnect_ivl (options.reconnect_ivl)
{
    zmq_assert (_addr);
    zmq_assert (_addr->protocol == "tipc");
    _addr->to_string (_endpoint);
    _socket = _session->get_socket ();
}

zmq::tipc_connecter_t::~tipc_connecter_t ()
{
    zmq_assert (!_timer_started);
    zmq_assert (!_handle_valid);
    zmq_assert (_s == retired_fd);
}

void zmq::tipc_connecter_t::process_plug ()
{
    if (_delayed_start)
        add_reconnect_timer ();
    else
        start_connecting ();
}

void zmq::tipc_connecter_t::process_term (int linger_)
{
    if (_timer_started) {
        cancel_timer (reconnect_timer_id);
        _timer_started = false;
    }

    if (_handle_valid) {
        rm_fd (_handle);
        _handle_valid = false;
    }

    if (_s != retired_fd)
        close ();

    own_t::process_term (linger_);
}

void zmq::tipc_connecter_t::in_event ()
{
    //  We are not polling for incoming data, so we are actually called
    //  because of error here. However, we can get error on out event as well
    //  on some platforms, so we'll simply handle both events in the same way.
    out_event ();
}

void zmq::tipc_connecter_t::out_event ()
{
    fd_t fd = connect ();
    rm_fd (_handle);
    _handle_valid = false;

    //  Handle the error condition by attempt to reconnect.
    if (fd == retired_fd) {
        close ();
        add_reconnect_timer ();
        return;
    }
    //  Create the engine object for this connection.
    stream_engine_t *engine =
      new (std::nothrow) stream_engine_t (fd, options, _endpoint);
    alloc_assert (engine);

    //  Attach the engine to the corresponding session object.
    send_attach (_session, engine);

    //  Shut the connecter down.
    terminate ();

    _socket->event_connected (_endpoint, fd);
}

void zmq::tipc_connecter_t::timer_event (int id_)
{
    zmq_assert (id_ == reconnect_timer_id);
    _timer_started = false;
    start_connecting ();
}

void zmq::tipc_connecter_t::start_connecting ()
{
    //  Open the connecting socket.
    int rc = open ();

    //  Connect may succeed in synchronous manner.
    if (rc == 0) {
        _handle = add_fd (_s);
        _handle_valid = true;
        out_event ();
    }

    //  Connection establishment may be delayed. Poll for its completion.
    else if (rc == -1 && errno == EINPROGRESS) {
        _handle = add_fd (_s);
        _handle_valid = true;
        set_pollout (_handle);
        _socket->event_connect_delayed (_endpoint, zmq_errno ());
    }

    //  Handle any other error condition by eventual reconnect.
    else {
        if (_s != retired_fd)
            close ();
        add_reconnect_timer ();
    }
}

void zmq::tipc_connecter_t::add_reconnect_timer ()
{
    if (options.reconnect_ivl != -1) {
        int rc_ivl = get_new_reconnect_ivl ();
        add_timer (rc_ivl, reconnect_timer_id);
        _socket->event_connect_retried (_endpoint, rc_ivl);
        _timer_started = true;
    }
}

int zmq::tipc_connecter_t::get_new_reconnect_ivl ()
{
    //  The new interval is the current interval + random value.
    int this_interval =
      _current_reconnect_ivl + (generate_random () % options.reconnect_ivl);

    //  Only change the current reconnect interval  if the maximum reconnect
    //  interval was set and if it's larger than the reconnect interval.
    if (options.reconnect_ivl_max > 0
        && options.reconnect_ivl_max > options.reconnect_ivl) {
        //  Calculate the next interval
        _current_reconnect_ivl = _current_reconnect_ivl * 2;
        if (_current_reconnect_ivl >= options.reconnect_ivl_max) {
            _current_reconnect_ivl = options.reconnect_ivl_max;
        }
    }
    return this_interval;
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
    if (_s == -1)
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

void zmq::tipc_connecter_t::close ()
{
    zmq_assert (_s != retired_fd);
    int rc = ::close (_s);
    errno_assert (rc == 0);
    _socket->event_closed (_endpoint, _s);
    _s = retired_fd;
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
    int rc = getsockopt (_s, SOL_SOCKET, SO_ERROR, (char *) &err, &len);
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
