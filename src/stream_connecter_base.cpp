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
#include "stream_connecter_base.hpp"
#include "session_base.hpp"
#include "address.hpp"
#include "random.hpp"

zmq::stream_connecter_base_t::stream_connecter_base_t (
  zmq::io_thread_t *io_thread_,
  zmq::session_base_t *session_,
  const zmq::options_t &options_,
  zmq::address_t *addr_,
  bool delayed_start_) :
    own_t (io_thread_, options_),
    io_object_t (io_thread_),
    _addr (addr_),
    _s (retired_fd),
    _handle (static_cast<handle_t> (NULL)),
    _delayed_start (delayed_start_),
    _reconnect_timer_started (false),
    _session (session_),
    _current_reconnect_ivl (options.reconnect_ivl),
    _socket (_session->get_socket ())
{
    zmq_assert (_addr);
    _addr->to_string (_endpoint);
    // TODO the return value is unused! what if it fails? if this is impossible
    // or does not matter, change such that endpoint in initialized using an
    // initializer, and make endpoint const
}

zmq::stream_connecter_base_t::~stream_connecter_base_t ()
{
    zmq_assert (!_reconnect_timer_started);
    zmq_assert (!_handle);
    zmq_assert (_s == retired_fd);
}

void zmq::stream_connecter_base_t::process_plug ()
{
    if (_delayed_start)
        add_reconnect_timer ();
    else
        start_connecting ();
}

void zmq::stream_connecter_base_t::process_term (int linger_)
{
    if (_reconnect_timer_started) {
        cancel_timer (reconnect_timer_id);
        _reconnect_timer_started = false;
    }

    if (_handle) {
        rm_handle ();
    }

    if (_s != retired_fd)
        close ();

    own_t::process_term (linger_);
}

void zmq::stream_connecter_base_t::add_reconnect_timer ()
{
    if (options.reconnect_ivl != -1) {
        const int interval = get_new_reconnect_ivl ();
        add_timer (interval, reconnect_timer_id);
        _socket->event_connect_retried (_endpoint, interval);
        _reconnect_timer_started = true;
    }
}

int zmq::stream_connecter_base_t::get_new_reconnect_ivl ()
{
    //  The new interval is the current interval + random value.
    const int interval =
      _current_reconnect_ivl + generate_random () % options.reconnect_ivl;

    //  Only change the current reconnect interval  if the maximum reconnect
    //  interval was set and if it's larger than the reconnect interval.
    if (options.reconnect_ivl_max > 0
        && options.reconnect_ivl_max > options.reconnect_ivl)
        //  Calculate the next interval
        _current_reconnect_ivl =
          std::min (_current_reconnect_ivl * 2, options.reconnect_ivl_max);
    return interval;
}

void zmq::stream_connecter_base_t::rm_handle ()
{
    rm_fd (_handle);
    _handle = static_cast<handle_t> (NULL);
}

void zmq::stream_connecter_base_t::close ()
{
    zmq_assert (_s != retired_fd);
#ifdef ZMQ_HAVE_WINDOWS
    const int rc = closesocket (_s);
    wsa_assert (rc != SOCKET_ERROR);
#else
    const int rc = ::close (_s);
    errno_assert (rc == 0);
#endif
    _socket->event_closed (_endpoint, _s);
    _s = retired_fd;
}
