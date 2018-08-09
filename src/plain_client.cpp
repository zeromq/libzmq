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

#include "precompiled.hpp"
#include "macros.hpp"

#include <string>
#include <limits.h>

#include "msg.hpp"
#include "err.hpp"
#include "plain_client.hpp"
#include "session_base.hpp"
#include "plain_common.hpp"

zmq::plain_client_t::plain_client_t (session_base_t *const session_,
                                     const options_t &options_) :
    mechanism_base_t (session_, options_),
    _state (sending_hello)
{
}

zmq::plain_client_t::~plain_client_t ()
{
}

int zmq::plain_client_t::next_handshake_command (msg_t *msg_)
{
    int rc = 0;

    switch (_state) {
        case sending_hello:
            produce_hello (msg_);
            _state = waiting_for_welcome;
            break;
        case sending_initiate:
            produce_initiate (msg_);
            _state = waiting_for_ready;
            break;
        default:
            errno = EAGAIN;
            rc = -1;
    }
    return rc;
}

int zmq::plain_client_t::process_handshake_command (msg_t *msg_)
{
    const unsigned char *cmd_data =
      static_cast<unsigned char *> (msg_->data ());
    const size_t data_size = msg_->size ();

    int rc = 0;
    if (data_size >= welcome_prefix_len
        && !memcmp (cmd_data, welcome_prefix, welcome_prefix_len))
        rc = process_welcome (cmd_data, data_size);
    else if (data_size >= ready_prefix_len
             && !memcmp (cmd_data, ready_prefix, ready_prefix_len))
        rc = process_ready (cmd_data, data_size);
    else if (data_size >= error_prefix_len
             && !memcmp (cmd_data, error_prefix, error_prefix_len))
        rc = process_error (cmd_data, data_size);
    else {
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (), ZMQ_PROTOCOL_ERROR_ZMTP_UNEXPECTED_COMMAND);
        errno = EPROTO;
        rc = -1;
    }

    if (rc == 0) {
        rc = msg_->close ();
        errno_assert (rc == 0);
        rc = msg_->init ();
        errno_assert (rc == 0);
    }

    return rc;
}

zmq::mechanism_t::status_t zmq::plain_client_t::status () const
{
    switch (_state) {
        case ready:
            return mechanism_t::ready;
        case error_command_received:
            return mechanism_t::error;
        default:
            return mechanism_t::handshaking;
    }
}

void zmq::plain_client_t::produce_hello (msg_t *msg_) const
{
    const std::string username = options.plain_username;
    zmq_assert (username.length () <= UCHAR_MAX);

    const std::string password = options.plain_password;
    zmq_assert (password.length () <= UCHAR_MAX);

    const size_t command_size = hello_prefix_len + brief_len_size
                                + username.length () + brief_len_size
                                + password.length ();

    const int rc = msg_->init_size (command_size);
    errno_assert (rc == 0);

    unsigned char *ptr = static_cast<unsigned char *> (msg_->data ());
    memcpy (ptr, hello_prefix, hello_prefix_len);
    ptr += hello_prefix_len;

    *ptr++ = static_cast<unsigned char> (username.length ());
    memcpy (ptr, username.c_str (), username.length ());
    ptr += username.length ();

    *ptr++ = static_cast<unsigned char> (password.length ());
    memcpy (ptr, password.c_str (), password.length ());
}

int zmq::plain_client_t::process_welcome (const unsigned char *cmd_data_,
                                          size_t data_size_)
{
    LIBZMQ_UNUSED (cmd_data_);

    if (_state != waiting_for_welcome) {
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (), ZMQ_PROTOCOL_ERROR_ZMTP_UNEXPECTED_COMMAND);
        errno = EPROTO;
        return -1;
    }
    if (data_size_ != welcome_prefix_len) {
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (),
          ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_WELCOME);
        errno = EPROTO;
        return -1;
    }
    _state = sending_initiate;
    return 0;
}

void zmq::plain_client_t::produce_initiate (msg_t *msg_) const
{
    make_command_with_basic_properties (msg_, initiate_prefix,
                                        initiate_prefix_len);
}

int zmq::plain_client_t::process_ready (const unsigned char *cmd_data_,
                                        size_t data_size_)
{
    if (_state != waiting_for_ready) {
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (), ZMQ_PROTOCOL_ERROR_ZMTP_UNEXPECTED_COMMAND);
        errno = EPROTO;
        return -1;
    }
    const int rc = parse_metadata (cmd_data_ + ready_prefix_len,
                                   data_size_ - ready_prefix_len);
    if (rc == 0)
        _state = ready;
    else
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (), ZMQ_PROTOCOL_ERROR_ZMTP_INVALID_METADATA);

    return rc;
}

int zmq::plain_client_t::process_error (const unsigned char *cmd_data_,
                                        size_t data_size_)
{
    if (_state != waiting_for_welcome && _state != waiting_for_ready) {
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (), ZMQ_PROTOCOL_ERROR_ZMTP_UNEXPECTED_COMMAND);
        errno = EPROTO;
        return -1;
    }
    const size_t start_of_error_reason = error_prefix_len + brief_len_size;
    if (data_size_ < start_of_error_reason) {
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (),
          ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_ERROR);
        errno = EPROTO;
        return -1;
    }
    const size_t error_reason_len =
      static_cast<size_t> (cmd_data_[error_prefix_len]);
    if (error_reason_len > data_size_ - start_of_error_reason) {
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (),
          ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_ERROR);
        errno = EPROTO;
        return -1;
    }
    const char *error_reason =
      reinterpret_cast<const char *> (cmd_data_) + start_of_error_reason;
    handle_error_reason (error_reason, error_reason_len);
    _state = error_command_received;
    return 0;
}
