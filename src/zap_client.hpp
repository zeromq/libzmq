/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_ZAP_CLIENT_HPP_INCLUDED__
#define __ZMQ_ZAP_CLIENT_HPP_INCLUDED__

#include "mechanism_base.hpp"

namespace zmq
{
class zap_client_t : public virtual mechanism_base_t
{
  public:
    zap_client_t (session_base_t *session_,
                  const std::string &peer_address_,
                  const options_t &options_);

    void send_zap_request (const char *mechanism_,
                           size_t mechanism_length_,
                           const uint8_t *credentials_,
                           size_t credentials_size_);

    void send_zap_request (const char *mechanism_,
                           size_t mechanism_length_,
                           const uint8_t **credentials_,
                           size_t *credentials_sizes_,
                           size_t credentials_count_);

    virtual int receive_and_process_zap_reply ();
    virtual void handle_zap_status_code ();

  protected:
    const std::string peer_address;

    //  Status code as received from ZAP handler
    std::string status_code;
};

class zap_client_common_handshake_t : public zap_client_t
{
  protected:
    enum state_t
    {
        waiting_for_hello,
        sending_welcome,
        waiting_for_initiate,
        waiting_for_zap_reply,
        sending_ready,
        sending_error,
        error_sent,
        ready
    };

    zap_client_common_handshake_t (session_base_t *session_,
                                   const std::string &peer_address_,
                                   const options_t &options_,
                                   state_t zap_reply_ok_state_);

    //  methods from mechanism_t
    status_t status () const ZMQ_FINAL;
    int zap_msg_available () ZMQ_FINAL;

    //  zap_client_t methods
    int receive_and_process_zap_reply () ZMQ_FINAL;
    void handle_zap_status_code () ZMQ_FINAL;

    //  Current FSM state
    state_t state;

  private:
    const state_t _zap_reply_ok_state;
};
}

#endif
