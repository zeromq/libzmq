/*
    Copyright (c) 2007-2014 Contributors as noted in the AUTHORS file

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

#include "ipc_connecter.hpp"

#if !defined ZMQ_HAVE_WINDOWS && !defined ZMQ_HAVE_OPENVMS

#include <new>
#include <string>

#include "stream_engine.hpp"
#include "io_thread.hpp"
#include "platform.hpp"
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
      class session_base_t *session_, const options_t &options_,
      const address_t *addr_, bool delayed_start_) :
    own_t (io_thread_, options_),
    io_object_t (io_thread_),
    addr (addr_),
    s (retired_fd),
    handle_valid (false),
    delayed_start (delayed_start_),
    timer_started (false),
    session (session_),
    current_reconnect_ivl(options.reconnect_ivl)
{
    zmq_assert (addr);
    zmq_assert (addr->protocol == "ipc");
    addr->to_string (endpoint);
    socket = session-> get_socket();
}

zmq::ipc_connecter_t::~ipc_connecter_t ()
{
    zmq_assert (!timer_started);
    zmq_assert (!handle_valid);
    zmq_assert (s == retired_fd);
}

void zmq::ipc_connecter_t::process_plug ()
{
    if (delayed_start)
        add_reconnect_timer ();
    else
        start_connecting ();
}

void zmq::ipc_connecter_t::process_term (int linger_)
{
    if (timer_started) {
        cancel_timer (reconnect_timer_id);
        timer_started = false;
    }

    if (handle_valid) {
        rm_fd (handle);
        handle_valid = false;
    }

    if (s != retired_fd)
        close ();

    own_t::process_term (linger_);
}

void zmq::ipc_connecter_t::in_event ()
{
    //  We are not polling for incomming data, so we are actually called
    //  because of error here. However, we can get error on out event as well
    //  on some platforms, so we'll simply handle both events in the same way.
    out_event ();
}

void zmq::ipc_connecter_t::out_event ()
{
    fd_t fd = connect ();
    rm_fd (handle);
    handle_valid = false;

    //  Handle the error condition by attempt to reconnect.
    if (fd == retired_fd) {
        close ();
        add_reconnect_timer();
        return;
    }
    //  Create the engine object for this connection.
    stream_engine_t *engine = new (std::nothrow)
        stream_engine_t (fd, options, endpoint);
    alloc_assert (engine);

    //  Attach the engine to the corresponding session object.
    send_attach (session, engine);

    //  Shut the connecter down.
    terminate ();

    socket->event_connected (endpoint, fd);
}

void zmq::ipc_connecter_t::timer_event (int id_)
{
    zmq_assert (id_ == reconnect_timer_id);
    timer_started = false;
    start_connecting ();
}

void zmq::ipc_connecter_t::start_connecting ()
{
    //  Open the connecting socket.
    int rc = open ();

    //  Connect may succeed in synchronous manner.
    if (rc == 0) {
        handle = add_fd (s);
        handle_valid = true;
        out_event ();
    }

    //  Connection establishment may be delayed. Poll for its completion.
    else
    if (rc == -1 && errno == EINPROGRESS) {
        handle = add_fd (s);
        handle_valid = true;
        set_pollout (handle);
        socket->event_connect_delayed (endpoint, zmq_errno());
    }

    //  Handle any other error condition by eventual reconnect.
    else {
        if (s != retired_fd)
            close ();
        add_reconnect_timer ();
    }
}

void zmq::ipc_connecter_t::add_reconnect_timer()
{
    int rc_ivl = get_new_reconnect_ivl();
    add_timer (rc_ivl, reconnect_timer_id);
    socket->event_connect_retried (endpoint, rc_ivl);
    timer_started = true;
}

int zmq::ipc_connecter_t::get_new_reconnect_ivl ()
{
    //  The new interval is the current interval + random value.
    int this_interval = current_reconnect_ivl +
        (generate_random () % options.reconnect_ivl);

    //  Only change the current reconnect interval  if the maximum reconnect
    //  interval was set and if it's larger than the reconnect interval.
    if (options.reconnect_ivl_max > 0 && 
        options.reconnect_ivl_max > options.reconnect_ivl) {

        //  Calculate the next interval
        current_reconnect_ivl = current_reconnect_ivl * 2;
        if(current_reconnect_ivl >= options.reconnect_ivl_max) {
            current_reconnect_ivl = options.reconnect_ivl_max;
        }   
    }
    return this_interval;
}

int zmq::ipc_connecter_t::open ()
{
    zmq_assert (s == retired_fd);

    //  Create the socket.
    s = open_socket (AF_UNIX, SOCK_STREAM, 0);
    if (s == -1)
        return -1;

    //  Set the non-blocking flag.
    unblock_socket (s);

    //  Connect to the remote peer.
    int rc = ::connect (
        s, addr->resolved.ipc_addr->addr (),
        addr->resolved.ipc_addr->addrlen ());

    //  Connect was successfull immediately.
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

int zmq::ipc_connecter_t::close ()
{
    zmq_assert (s != retired_fd);
    int rc = ::close (s);
    errno_assert (rc == 0);
    socket->event_closed (endpoint, s);
    s = retired_fd;
    return 0;
}

zmq::fd_t zmq::ipc_connecter_t::connect ()
{
    //  Following code should handle both Berkeley-derived socket
    //  implementations and Solaris.
    int err = 0;
#if defined ZMQ_HAVE_HPUX
    int len = sizeof (err);
#else
    socklen_t len = sizeof (err);
#endif
    int rc = getsockopt (s, SOL_SOCKET, SO_ERROR, (char*) &err, &len);
    if (rc == -1)
        err = errno;
    if (err != 0) {

        //  Assert if the error was caused by 0MQ bug.
        //  Networking problems are OK. No need to assert.
        errno = err;
        errno_assert (errno == ECONNREFUSED || errno == ECONNRESET ||
            errno == ETIMEDOUT || errno == EHOSTUNREACH ||
            errno == ENETUNREACH || errno == ENETDOWN);

        return retired_fd;
    }

    fd_t result = s;
    s = retired_fd;
    return result;
}

#endif

