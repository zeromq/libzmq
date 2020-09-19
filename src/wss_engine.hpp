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

#ifndef __ZMQ_WSS_ENGINE_HPP_INCLUDED__
#define __ZMQ_WSS_ENGINE_HPP_INCLUDED__

#include <gnutls/gnutls.h>
#include "ws_engine.hpp"

#define WSS_BUFFER_SIZE 8192

namespace zmq
{
class wss_engine_t : public ws_engine_t
{
  public:
    wss_engine_t (fd_t fd_,
                  const options_t &options_,
                  const endpoint_uri_pair_t &endpoint_uri_pair_,
                  ws_address_t &address_,
                  bool client_,
                  void *tls_server_cred_,
                  const std::string &hostname_);
    ~wss_engine_t ();

    void out_event ();

  protected:
    bool handshake ();
    void plug_internal ();
    int read (void *data, size_t size_);
    int write (const void *data_, size_t size_);

  private:
    bool do_handshake ();

    bool _established;
    gnutls_certificate_credentials_t _tls_client_cred;
    gnutls_session_t _tls_session;
};
}

#endif
