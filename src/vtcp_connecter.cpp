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

#include "vtcp_connecter.hpp"

#if defined ZMQ_HAVE_VTCP

#include <new>
#include <string>

#include "tcp_engine.hpp"
#include "io_thread.hpp"
#include "platform.hpp"
#include "likely.hpp"
#include "ip.hpp"
#include "err.hpp"

#if defined ZMQ_HAVE_WINDOWS
#include "windows.hpp"
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#ifdef ZMQ_HAVE_OPENVMS
#include <ioctl.h>
#endif
#endif

zmq::vtcp_connecter_t::vtcp_connecter_t (class io_thread_t *io_thread_,
      class session_t *session_, const options_t &options_,
      const char *address_, bool wait_) :
    own_t (io_thread_, options_),
    io_object_t (io_thread_),
    s (retired_fd),
    handle_valid (false),
    wait (wait_),
    session (session_),
    current_reconnect_ivl(options.reconnect_ivl)
{
    memset (&addr, 0, sizeof (addr));
    addr_len = 0;
    subport = 0;

    int rc = set_address (address_);
    zmq_assert (rc == 0);
}

zmq::vtcp_connecter_t::~vtcp_connecter_t ()
{
    if (wait)
        cancel_timer (reconnect_timer_id);
    if (handle_valid)
        rm_fd (handle);

    if (s != retired_fd)
        close ();
}

int zmq::vtcp_connecter_t::set_address (const char *addr_)
{
    const char *delimiter = strrchr (addr_, '.');
    if (!delimiter) {
        errno = EINVAL;
        return -1;
    }
    std::string addr_str (addr_, delimiter - addr_);
    std::string subport_str (delimiter + 1);
    subport = (vtcp_subport_t) atoi (subport_str.c_str ());
    int rc = resolve_ip_hostname (&addr, &addr_len, addr_str.c_str ());
    if (rc != 0)
        return -1;

    return 0;
}

void zmq::vtcp_connecter_t::process_plug ()
{
    if (wait)
        add_reconnect_timer();
    else
        start_connecting ();
}

void zmq::vtcp_connecter_t::in_event ()
{
    //  We are not polling for incomming data, so we are actually called
    //  because of error here. However, we can get error on out event as well
    //  on some platforms, so we'll simply handle both events in the same way.
    out_event ();
}

void zmq::vtcp_connecter_t::out_event ()
{
    fd_t fd = connect ();
    rm_fd (handle);
    handle_valid = false;

    //  Handle the error condition by attempt to reconnect.
    if (fd == retired_fd) {
        close ();
        wait = true;
        add_reconnect_timer();
        return;
    }

    //  Create the engine object for this connection.
    tcp_engine_t *engine = new (std::nothrow) tcp_engine_t (fd, options);
    alloc_assert (engine);

    //  Attach the engine to the corresponding session object.
    send_attach (session, engine);

    //  Shut the connecter down.
    terminate ();
}

void zmq::vtcp_connecter_t::timer_event (int id_)
{
    zmq_assert (id_ == reconnect_timer_id);
    wait = false;
    start_connecting ();
}

void zmq::vtcp_connecter_t::start_connecting ()
{
    //  Open the connecting socket.
    int rc = open ();

    //  Handle error condition by eventual reconnect.
    if (unlikely (rc != 0)) {
        errno_assert (false);
        wait = true;
        add_reconnect_timer();
        return;
    }

    //  Connection establishment may be dealyed. Poll for its completion.
    handle = add_fd (s);
    handle_valid = true;
    set_pollout (handle);
}

void zmq::vtcp_connecter_t::add_reconnect_timer()
{
    add_timer (get_new_reconnect_ivl(), reconnect_timer_id);
}

int zmq::vtcp_connecter_t::get_new_reconnect_ivl ()
{
#if defined ZMQ_HAVE_WINDOWS
    int pid = (int) GetCurrentProcessId ();
#else
    int pid = (int) getpid ();
#endif

    //  The new interval is the current interval + random value.
    int this_interval = current_reconnect_ivl +
        ((pid * 13) % options.reconnect_ivl);

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

int zmq::vtcp_connecter_t::open ()
{
    zmq_assert (s == retired_fd);

    //  Start the connection procedure.
    sockaddr_in *paddr = (sockaddr_in*) &addr;
    s = vtcp_connect (paddr->sin_addr.s_addr, ntohs (paddr->sin_port));

    //  Connect was successfull immediately.
    if (s != retired_fd)
        return 0;

    //  Asynchronous connect was launched.
    if (errno == EINPROGRESS) {
        errno = EAGAIN;
        return -1;
    }

    //  Error occured.
    return -1;
}

zmq::fd_t zmq::vtcp_connecter_t::connect ()
{
    int rc = vtcp_acceptc (s, subport);
    if (rc != 0) {
        int err = errno;
        close ();
        errno = err;
        return retired_fd;
    }

    // Set to non-blocking mode.
#ifdef ZMQ_HAVE_OPENVMS
	int flags = 1;
	rc = ioctl (s, FIONBIO, &flags);
    errno_assert (rc != -1);
#else
	int flags = fcntl (s, F_GETFL, 0);
	if (flags == -1)
        flags = 0;
	rc = fcntl (s, F_SETFL, flags | O_NONBLOCK);
    errno_assert (rc != -1);
#endif

    //  Disable Nagle's algorithm.
    int flag = 1;
    rc = setsockopt (s, IPPROTO_TCP, TCP_NODELAY, (char*) &flag,
        sizeof (int));
    errno_assert (rc == 0);

#ifdef ZMQ_HAVE_OPENVMS
    //  Disable delayed acknowledgements.
    flag = 1;
    rc = setsockopt (s, IPPROTO_TCP, TCP_NODELACK, (char*) &flag,
        sizeof (int));
    errno_assert (rc != SOCKET_ERROR);
#endif

    fd_t result = s;
    s = retired_fd;
    return result;
}

int zmq::vtcp_connecter_t::close ()
{
    zmq_assert (s != retired_fd);
    int rc = ::close (s);
    if (rc != 0)
        return -1;
    s = retired_fd;
    return 0;
}

#endif

