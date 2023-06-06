/* SPDX-License-Identifier: MPL-2.0 */

#include "precompiled.hpp"

#include "mechanism_base.hpp"
#include "session_base.hpp"

zmq::mechanism_base_t::mechanism_base_t (session_base_t *const session_,
                                         const options_t &options_) :
    mechanism_t (options_), session (session_)
{
}

int zmq::mechanism_base_t::check_basic_command_structure (msg_t *msg_) const
{
    if (msg_->size () <= 1
        || msg_->size () <= (static_cast<uint8_t *> (msg_->data ()))[0]) {
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (),
          ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_UNSPECIFIED);
        errno = EPROTO;
        return -1;
    }
    return 0;
}

void zmq::mechanism_base_t::handle_error_reason (const char *error_reason_,
                                                 size_t error_reason_len_)
{
    const size_t status_code_len = 3;
    const char zero_digit = '0';
    const size_t significant_digit_index = 0;
    const size_t first_zero_digit_index = 1;
    const size_t second_zero_digit_index = 2;
    const int factor = 100;
    if (error_reason_len_ == status_code_len
        && error_reason_[first_zero_digit_index] == zero_digit
        && error_reason_[second_zero_digit_index] == zero_digit
        && error_reason_[significant_digit_index] >= '3'
        && error_reason_[significant_digit_index] <= '5') {
        // it is a ZAP error status code (300, 400 or 500), so emit an authentication failure event
        session->get_socket ()->event_handshake_failed_auth (
          session->get_endpoint (),
          (error_reason_[significant_digit_index] - zero_digit) * factor);
    } else {
        // this is a violation of the ZAP protocol
        // TODO zmq_assert in this case?
    }
}

bool zmq::mechanism_base_t::zap_required () const
{
    return !options.zap_domain.empty ();
}
