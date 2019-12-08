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
#include "stream_listener_base.hpp"
#include "session_base.hpp"
#include "socket_base.hpp"
#include "zmtp_engine.hpp"
#include "raw_engine.hpp"

#ifndef ZMQ_HAVE_WINDOWS
#include <unistd.h>
#else
#include <winsock2.h>
#endif

zmq::stream_listener_base_t::stream_listener_base_t (
  zmq::io_thread_t *io_thread_,
  zmq::socket_base_t *socket_,
  const zmq::options_t &options_) :
    own_t (io_thread_, options_),
    io_object_t (io_thread_),
    _s (retired_fd),
    _handle (static_cast<handle_t> (NULL)),
    _socket (socket_)
{
}

zmq::stream_listener_base_t::~stream_listener_base_t ()
{
    zmq_assert (_s == retired_fd);
    zmq_assert (!_handle);
}

int zmq::stream_listener_base_t::get_local_address (std::string &addr_) const
{
    addr_ = get_socket_name (_s, socket_end_local);
    return addr_.empty () ? -1 : 0;
}

void zmq::stream_listener_base_t::process_plug ()
{
    //  Start polling for incoming connections.
    _handle = add_fd (_s);
    set_pollin (_handle);
}

void zmq::stream_listener_base_t::process_term (int linger_)
{
    rm_fd (_handle);
    _handle = static_cast<handle_t> (NULL);
    close ();
    own_t::process_term (linger_);
}

int zmq::stream_listener_base_t::close ()
{
    // TODO this is identical to stream_connector_base_t::close

    zmq_assert (_s != retired_fd);
#ifdef ZMQ_HAVE_WINDOWS
    const int rc = closesocket (_s);
    wsa_assert (rc != SOCKET_ERROR);
#else
    const int rc = ::close (_s);
    errno_assert (rc == 0);
#endif
    _socket->event_closed (make_unconnected_bind_endpoint_pair (_endpoint), _s);
    _s = retired_fd;

    return 0;
}

void zmq::stream_listener_base_t::create_engine (fd_t fd_)
{
    const endpoint_uri_pair_t endpoint_pair (
      get_socket_name (fd_, socket_end_local),
      get_socket_name (fd_, socket_end_remote), endpoint_type_bind);

    i_engine *engine;
    if (options.raw_socket)
        engine = new (std::nothrow) raw_engine_t (fd_, options, endpoint_pair);
    else
        engine = new (std::nothrow) zmtp_engine_t (fd_, options, endpoint_pair);
    alloc_assert (engine);

    //  Choose I/O thread to run connecter in. Given that we are already
    //  running in an I/O thread, there must be at least one available.
    io_thread_t *io_thread = choose_io_thread (options.affinity);
    zmq_assert (io_thread);

    //  Create and launch a session object.
    session_base_t *session =
      session_base_t::create (io_thread, false, _socket, options, NULL);
    errno_assert (session);
    session->inc_seqnum ();
    launch_child (session);
    send_attach (session, engine, false);

    _socket->event_accepted (endpoint_pair, fd_);
}
