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

#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include "err.hpp"
#include "msg.hpp"
#include "session_base.hpp"
#include "null_mechanism.hpp"

const char error_command_name[] = "\5ERROR";
const size_t error_command_name_len = sizeof (error_command_name) - 1;
const size_t error_reason_len_size = 1;

const char ready_command_name[] = "\5READY";
const size_t ready_command_name_len = sizeof (ready_command_name) - 1;

zmq::null_mechanism_t::null_mechanism_t (session_base_t *session_,
                                         const std::string &peer_address_,
                                         const options_t &options_) :
    mechanism_base_t (session_, options_),
    zap_client_t (session_, peer_address_, options_),
    _ready_command_sent (false),
    _error_command_sent (false),
    _ready_command_received (false),
    _error_command_received (false),
    _zap_request_sent (false),
    _zap_reply_received (false)
{
}

zmq::null_mechanism_t::~null_mechanism_t ()
{
}

int zmq::null_mechanism_t::next_handshake_command (msg_t *msg_)
{
    if (_ready_command_sent || _error_command_sent) {
        errno = EAGAIN;
        return -1;
    }

    if (zap_required () && !_zap_reply_received) {
        if (_zap_request_sent) {
            errno = EAGAIN;
            return -1;
        }
        //  Given this is a backward-incompatible change, it's behind a socket
        //  option disabled by default.
        int rc = session->zap_connect ();
        if (rc == -1 && options.zap_enforce_domain) {
            session->get_socket ()->event_handshake_failed_no_detail (
              session->get_endpoint (), EFAULT);
            return -1;
        }
        if (rc == 0) {
            send_zap_request ();
            _zap_request_sent = true;

            //  TODO actually, it is quite unlikely that we can read the ZAP
            //  reply already, but removing this has some strange side-effect
            //  (probably because the pipe's in_active flag is true until a read
            //  is attempted)
            rc = receive_and_process_zap_reply ();
            if (rc != 0)
                return -1;

            _zap_reply_received = true;
        }
    }

    if (_zap_reply_received && status_code != "200") {
        _error_command_sent = true;
        if (status_code != "300") {
            const size_t status_code_len = 3;
            const int rc = msg_->init_size (
              error_command_name_len + error_reason_len_size + status_code_len);
            zmq_assert (rc == 0);
            unsigned char *msg_data =
              static_cast<unsigned char *> (msg_->data ());
            memcpy (msg_data, error_command_name, error_command_name_len);
            msg_data += error_command_name_len;
            *msg_data = status_code_len;
            msg_data += error_reason_len_size;
            memcpy (msg_data, status_code.c_str (), status_code_len);
            return 0;
        }
        errno = EAGAIN;
        return -1;
    }

    make_command_with_basic_properties (msg_, ready_command_name,
                                        ready_command_name_len);

    _ready_command_sent = true;

    return 0;
}

int zmq::null_mechanism_t::process_handshake_command (msg_t *msg_)
{
    if (_ready_command_received || _error_command_received) {
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (), ZMQ_PROTOCOL_ERROR_ZMTP_UNEXPECTED_COMMAND);
        errno = EPROTO;
        return -1;
    }

    const unsigned char *cmd_data =
      static_cast<unsigned char *> (msg_->data ());
    const size_t data_size = msg_->size ();

    int rc = 0;
    if (data_size >= ready_command_name_len
        && !memcmp (cmd_data, ready_command_name, ready_command_name_len))
        rc = process_ready_command (cmd_data, data_size);
    else if (data_size >= error_command_name_len
             && !memcmp (cmd_data, error_command_name, error_command_name_len))
        rc = process_error_command (cmd_data, data_size);
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

int zmq::null_mechanism_t::process_ready_command (
  const unsigned char *cmd_data_, size_t data_size_)
{
    _ready_command_received = true;
    return parse_metadata (cmd_data_ + ready_command_name_len,
                           data_size_ - ready_command_name_len);
}

int zmq::null_mechanism_t::process_error_command (
  const unsigned char *cmd_data_, size_t data_size_)
{
    const size_t fixed_prefix_size =
      error_command_name_len + error_reason_len_size;
    if (data_size_ < fixed_prefix_size) {
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (),
          ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_ERROR);

        errno = EPROTO;
        return -1;
    }
    const size_t error_reason_len =
      static_cast<size_t> (cmd_data_[error_command_name_len]);
    if (error_reason_len > data_size_ - fixed_prefix_size) {
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (),
          ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_ERROR);

        errno = EPROTO;
        return -1;
    }
    const char *error_reason =
      reinterpret_cast<const char *> (cmd_data_) + fixed_prefix_size;
    handle_error_reason (error_reason, error_reason_len);
    _error_command_received = true;
    return 0;
}

int zmq::null_mechanism_t::zap_msg_available ()
{
    if (_zap_reply_received) {
        errno = EFSM;
        return -1;
    }
    const int rc = receive_and_process_zap_reply ();
    if (rc == 0)
        _zap_reply_received = true;
    return rc == -1 ? -1 : 0;
}

zmq::mechanism_t::status_t zmq::null_mechanism_t::status () const
{
    if (_ready_command_sent && _ready_command_received)
        return ready;

    const bool command_sent = _ready_command_sent || _error_command_sent;
    const bool command_received =
      _ready_command_received || _error_command_received;
    return command_sent && command_received ? error : handshaking;
}

void zmq::null_mechanism_t::send_zap_request ()
{
    zap_client_t::send_zap_request ("NULL", 4, NULL, NULL, 0);
}
