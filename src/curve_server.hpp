/* SPDX-License-Identifier: MPL-2.0 */

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
class curve_server_t ZMQ_FINAL : public zap_client_common_handshake_t,
                                 public curve_mechanism_base_t
{
  public:
    curve_server_t (session_base_t *session_,
                    const std::string &peer_address_,
                    const options_t &options_,
                    const bool downgrade_sub_);
    ~curve_server_t ();

    // mechanism implementation
    int next_handshake_command (msg_t *msg_);
    int process_handshake_command (msg_t *msg_);
    int encode (msg_t *msg_);
    int decode (msg_t *msg_);

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
