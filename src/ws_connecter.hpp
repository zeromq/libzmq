/*
    Copyright (c) 2007-2019 Contributors as noted in the AUTHORS file

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

#ifndef __WS_CONNECTER_HPP_INCLUDED__
#define __WS_CONNECTER_HPP_INCLUDED__

#include "fd.hpp"
#include "stdint.hpp"
#include "stream_connecter_base.hpp"

namespace zmq
{
class ws_connecter_t ZMQ_FINAL : public stream_connecter_base_t
{
  public:
    //  If 'delayed_start' is true connecter first waits for a while,
    //  then starts connection process.
    ws_connecter_t (zmq::io_thread_t *io_thread_,
                    zmq::session_base_t *session_,
                    const options_t &options_,
                    address_t *addr_,
                    bool delayed_start_,
                    bool wss_,
                    const std::string &tls_hostname_);
    ~ws_connecter_t ();

  protected:
    void create_engine (fd_t fd, const std::string &local_address_);

  private:
    //  ID of the timer used to check the connect timeout, must be different from stream_connecter_base_t::reconnect_timer_id.
    enum
    {
        connect_timer_id = 2
    };

    //  Handlers for incoming commands.
    void process_term (int linger_);

    //  Handlers for I/O events.
    void out_event ();
    void timer_event (int id_);

    //  Internal function to start the actual connection establishment.
    void start_connecting ();

    //  Internal function to add a connect timer
    void add_connect_timer ();

    //  Open TCP connecting socket. Returns -1 in case of error,
    //  0 if connect was successful immediately. Returns -1 with
    //  EAGAIN errno if async connect was launched.
    int open ();

    //  Get the file descriptor of newly created connection. Returns
    //  retired_fd if the connection was unsuccessful.
    fd_t connect ();

    //  Tunes a connected socket.
    bool tune_socket (fd_t fd_);

    //  True iff a timer has been started.
    bool _connect_timer_started;

    bool _wss;
    const std::string &_hostname;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (ws_connecter_t)
};
}

#endif
