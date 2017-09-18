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

#include "mechanism_base.hpp"
#include "session_base.hpp"

zmq::mechanism_base_t::mechanism_base_t (session_base_t *const session_,
                                         const options_t &options_) :
    mechanism_t (options_),
    session (session_)
{

}

int zmq::mechanism_base_t::check_basic_command_structure (msg_t *msg_)
{
    if (msg_->size () <= 1 || msg_->size () <= ((uint8_t *) msg_->data ())[0]) {
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (),
          ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_UNSPECIFIED);
        errno = EPROTO;
        return -1;
    }
    return 0;
}

void zmq::mechanism_base_t::handle_error_reason (const char *error_reason,
                                                 size_t error_reason_len)
{
    if (error_reason_len == 3 && error_reason[1] == '0'
        && error_reason[2] == '0' && error_reason[0] >= '3'
        && error_reason[0] <= '5') {
        // it is a ZAP status code, so emit an authentication failure event
        session->get_socket ()->event_handshake_failed_auth (
          session->get_endpoint (), (error_reason[0] - '0') * 100);
    }
}

bool zmq::mechanism_base_t::zap_required() const
{
    return !options.zap_domain.empty ();
}
