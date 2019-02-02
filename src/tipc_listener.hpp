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

#ifndef __ZMQ_TIPC_LISTENER_HPP_INCLUDED__
#define __ZMQ_TIPC_LISTENER_HPP_INCLUDED__

#include "platform.hpp"

#if defined ZMQ_HAVE_TIPC

#include <string>

#include "fd.hpp"
#include "stream_listener_base.hpp"
#include "tipc_address.hpp"

namespace zmq
{
class tipc_listener_t : public stream_listener_base_t
{
  public:
    tipc_listener_t (zmq::io_thread_t *io_thread_,
                     zmq::socket_base_t *socket_,
                     const options_t &options_);

    //  Set address to listen on.
    int set_local_address (const char *addr_);

  protected:
    std::string get_socket_name (fd_t fd_, socket_end_t socket_end_) const;

  private:
    //  Handlers for I/O events.
    void in_event ();

    //  Accept the new connection. Returns the file descriptor of the
    //  newly created connection. The function may return retired_fd
    //  if the connection was dropped while waiting in the listen backlog.
    fd_t accept ();

    // Address to listen on
    tipc_address_t _address;

    tipc_listener_t (const tipc_listener_t &);
    const tipc_listener_t &operator= (const tipc_listener_t &);
};
}

#endif

#endif
