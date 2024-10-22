/* SPDX-License-Identifier: MPL-2.0 */

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
