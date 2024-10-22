/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_NULL_MECHANISM_HPP_INCLUDED__
#define __ZMQ_NULL_MECHANISM_HPP_INCLUDED__

#include "mechanism.hpp"
#include "options.hpp"
#include "zap_client.hpp"

namespace zmq
{
class msg_t;
class session_base_t;

class null_mechanism_t ZMQ_FINAL : public zap_client_t
{
  public:
    null_mechanism_t (session_base_t *session_,
                      const std::string &peer_address_,
                      const options_t &options_);
    ~null_mechanism_t ();

    // mechanism implementation
    int next_handshake_command (msg_t *msg_);
    int process_handshake_command (msg_t *msg_);
    int zap_msg_available ();
    status_t status () const;

  private:
    bool _ready_command_sent;
    bool _error_command_sent;
    bool _ready_command_received;
    bool _error_command_received;
    bool _zap_request_sent;
    bool _zap_reply_received;

    int process_ready_command (const unsigned char *cmd_data_,
                               size_t data_size_);
    int process_error_command (const unsigned char *cmd_data_,
                               size_t data_size_);

    void send_zap_request ();
};
}

#endif
