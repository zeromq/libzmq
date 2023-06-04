/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_PLAIN_CLIENT_HPP_INCLUDED__
#define __ZMQ_PLAIN_CLIENT_HPP_INCLUDED__

#include "mechanism_base.hpp"
#include "options.hpp"

namespace zmq
{
class msg_t;

class plain_client_t ZMQ_FINAL : public mechanism_base_t
{
  public:
    plain_client_t (session_base_t *session_, const options_t &options_);
    ~plain_client_t ();

    // mechanism implementation
    int next_handshake_command (msg_t *msg_);
    int process_handshake_command (msg_t *msg_);
    status_t status () const;

  private:
    enum state_t
    {
        sending_hello,
        waiting_for_welcome,
        sending_initiate,
        waiting_for_ready,
        error_command_received,
        ready
    };

    state_t _state;

    void produce_hello (msg_t *msg_) const;
    void produce_initiate (msg_t *msg_) const;

    int process_welcome (const unsigned char *cmd_data_, size_t data_size_);
    int process_ready (const unsigned char *cmd_data_, size_t data_size_);
    int process_error (const unsigned char *cmd_data_, size_t data_size_);
};
}

#endif
