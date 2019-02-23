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

#ifndef __ZMQ_CURVE_SERVER_HPP_INCLUDED__
#define __ZMQ_CURVE_SERVER_HPP_INCLUDED__

#ifdef ZMQ_HAVE_CURVE

#include "curve_mechanism_base.hpp"
#include "options.hpp"
#include "zap_client.hpp"

namespace zmq
{
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4250)
#endif
class curve_server_t : public zap_client_common_handshake_t,
                       public curve_mechanism_base_t
{
  public:
    curve_server_t (session_base_t *session_,
                    const std::string &peer_address_,
                    const options_t &options_);
    virtual ~curve_server_t ();

    // mechanism implementation
    virtual int next_handshake_command (msg_t *msg_);
    virtual int process_handshake_command (msg_t *msg_);
    virtual int encode (msg_t *msg_);
    virtual int decode (msg_t *msg_);

  private:
    //  Our secret key (s)
    uint8_t _secret_key[crypto_box_SECRETKEYBYTES];

    //  Our short-term public key (S')
    uint8_t _cn_public[crypto_box_PUBLICKEYBYTES];

    //  Our short-term secret key (s')
    uint8_t _cn_secret[crypto_box_SECRETKEYBYTES];

    //  Client's short-term public key (C')
    uint8_t _cn_client[crypto_box_PUBLICKEYBYTES];

    //  Key used to produce cookie
    uint8_t _cookie_key[crypto_secretbox_KEYBYTES];

    int process_hello (msg_t *msg_);
    int produce_welcome (msg_t *msg_);
    int process_initiate (msg_t *msg_);
    int produce_ready (msg_t *msg_);
    int produce_error (msg_t *msg_) const;

    void send_zap_request (const uint8_t *key_);
};
#ifdef _MSC_VER
#pragma warning(pop)
#endif
}

#endif

#endif
