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

#ifndef __TIPC_CONNECTER_HPP_INCLUDED__
#define __TIPC_CONNECTER_HPP_INCLUDED__

#include "platform.hpp"

#if defined ZMQ_HAVE_TIPC

#include "fd.hpp"
#include "stream_connecter_base.hpp"

namespace zmq
{
class tipc_connecter_t : public stream_connecter_base_t
{
  public:
    //  If 'delayed_start' is true connecter first waits for a while,
    //  then starts connection process.
    tipc_connecter_t (zmq::io_thread_t *io_thread_,
                      zmq::session_base_t *session_,
                      const options_t &options_,
                      address_t *addr_,
                      bool delayed_start_);

  private:
    //  Handlers for I/O events.
    void out_event ();

    //  Internal function to start the actual connection establishment.
    void start_connecting ();

    //  Get the file descriptor of newly created connection. Returns
    //  retired_fd if the connection was unsuccessful.
    fd_t connect ();

    //  Open IPC connecting socket. Returns -1 in case of error,
    //  0 if connect was successful immediately. Returns -1 with
    //  EAGAIN errno if async connect was launched.
    int open ();

    tipc_connecter_t (const tipc_connecter_t &);
    const tipc_connecter_t &operator= (const tipc_connecter_t &);
};
}

#endif

#endif
