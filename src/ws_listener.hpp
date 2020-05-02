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

#ifndef __ZMQ_WS_LISTENER_HPP_INCLUDED__
#define __ZMQ_WS_LISTENER_HPP_INCLUDED__

#include "fd.hpp"
#include "ws_address.hpp"
#include "stream_listener_base.hpp"

#ifdef ZMQ_USE_GNUTLS
#include <gnutls/gnutls.h>
#endif

namespace zmq
{
class ws_listener_t ZMQ_FINAL : public stream_listener_base_t
{
  public:
    ws_listener_t (zmq::io_thread_t *io_thread_,
                   zmq::socket_base_t *socket_,
                   const options_t &options_,
                   bool wss_);

    ~ws_listener_t ();

    //  Set address to listen on.
    int set_local_address (const char *addr_);

  protected:
    std::string get_socket_name (fd_t fd_, socket_end_t socket_end_) const;
    void create_engine (fd_t fd);

  private:
    //  Handlers for I/O events.
    void in_event ();

    //  Accept the new connection. Returns the file descriptor of the
    //  newly created connection. The function may return retired_fd
    //  if the connection was dropped while waiting in the listen backlog
    //  or was denied because of accept filters.
    fd_t accept ();

    int create_socket (const char *addr_);

    //  Address to listen on.
    ws_address_t _address;

    bool _wss;
#ifdef ZMQ_HAVE_WSS
    gnutls_certificate_credentials_t _tls_cred;
#endif

    ZMQ_NON_COPYABLE_NOR_MOVABLE (ws_listener_t)
};
}

#endif
