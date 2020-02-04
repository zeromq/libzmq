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

#ifndef __ZMQ_PLAIN_SERVER_HPP_INCLUDED__
#define __ZMQ_PLAIN_SERVER_HPP_INCLUDED__

#include "options.hpp"
#include "zap_client.hpp"

namespace zmq
{
class msg_t;
class session_base_t;

class plain_server_t ZMQ_FINAL : public zap_client_common_handshake_t
{
  public:
    plain_server_t (session_base_t *session_,
                    const std::string &peer_address_,
                    const options_t &options_);
    ~plain_server_t ();

    // mechanism implementation
    int next_handshake_command (msg_t *msg_);
    int process_handshake_command (msg_t *msg_);

  private:
    static void produce_welcome (msg_t *msg_);
    void produce_ready (msg_t *msg_) const;
    void produce_error (msg_t *msg_) const;

    int process_hello (msg_t *msg_);
    int process_initiate (msg_t *msg_);

    void send_zap_request (const std::string &username_,
                           const std::string &password_);
};
}

#endif
