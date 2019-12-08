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

#include "zap_client.hpp"
#include "msg.hpp"
#include "session_base.hpp"

namespace zmq
{
const char zap_version[] = "1.0";
const size_t zap_version_len = sizeof (zap_version) - 1;

const char id[] = "1";
const size_t id_len = sizeof (id) - 1;

zap_client_t::zap_client_t (session_base_t *const session_,
                            const std::string &peer_address_,
                            const options_t &options_) :
    mechanism_base_t (session_, options_),
    peer_address (peer_address_)
{
}

void zap_client_t::send_zap_request (const char *mechanism_,
                                     size_t mechanism_length_,
                                     const uint8_t *credentials_,
                                     size_t credentials_size_)
{
    send_zap_request (mechanism_, mechanism_length_, &credentials_,
                      &credentials_size_, 1);
}

void zap_client_t::send_zap_request (const char *mechanism_,
                                     size_t mechanism_length_,
                                     const uint8_t **credentials_,
                                     size_t *credentials_sizes_,
                                     size_t credentials_count_)
{
    // write_zap_msg cannot fail. It could only fail if the HWM was exceeded,
    // but on the ZAP socket, the HWM is disabled.

    int rc;
    msg_t msg;

    //  Address delimiter frame
    rc = msg.init ();
    errno_assert (rc == 0);
    msg.set_flags (msg_t::more);
    rc = session->write_zap_msg (&msg);
    errno_assert (rc == 0);

    //  Version frame
    rc = msg.init_size (zap_version_len);
    errno_assert (rc == 0);
    memcpy (msg.data (), zap_version, zap_version_len);
    msg.set_flags (msg_t::more);
    rc = session->write_zap_msg (&msg);
    errno_assert (rc == 0);

    //  Request ID frame
    rc = msg.init_size (id_len);
    errno_assert (rc == 0);
    memcpy (msg.data (), id, id_len);
    msg.set_flags (msg_t::more);
    rc = session->write_zap_msg (&msg);
    errno_assert (rc == 0);

    //  Domain frame
    rc = msg.init_size (options.zap_domain.length ());
    errno_assert (rc == 0);
    memcpy (msg.data (), options.zap_domain.c_str (),
            options.zap_domain.length ());
    msg.set_flags (msg_t::more);
    rc = session->write_zap_msg (&msg);
    errno_assert (rc == 0);

    //  Address frame
    rc = msg.init_size (peer_address.length ());
    errno_assert (rc == 0);
    memcpy (msg.data (), peer_address.c_str (), peer_address.length ());
    msg.set_flags (msg_t::more);
    rc = session->write_zap_msg (&msg);
    errno_assert (rc == 0);

    //  Routing id frame
    rc = msg.init_size (options.routing_id_size);
    errno_assert (rc == 0);
    memcpy (msg.data (), options.routing_id, options.routing_id_size);
    msg.set_flags (msg_t::more);
    rc = session->write_zap_msg (&msg);
    errno_assert (rc == 0);

    //  Mechanism frame
    rc = msg.init_size (mechanism_length_);
    errno_assert (rc == 0);
    memcpy (msg.data (), mechanism_, mechanism_length_);
    if (credentials_count_)
        msg.set_flags (msg_t::more);
    rc = session->write_zap_msg (&msg);
    errno_assert (rc == 0);

    //  Credentials frames
    for (size_t i = 0; i < credentials_count_; ++i) {
        rc = msg.init_size (credentials_sizes_[i]);
        errno_assert (rc == 0);
        if (i < credentials_count_ - 1)
            msg.set_flags (msg_t::more);
        memcpy (msg.data (), credentials_[i], credentials_sizes_[i]);
        rc = session->write_zap_msg (&msg);
        errno_assert (rc == 0);
    }
}

int zap_client_t::receive_and_process_zap_reply ()
{
    int rc = 0;
    const size_t zap_reply_frame_count = 7;
    msg_t msg[zap_reply_frame_count];

    //  Initialize all reply frames
    for (size_t i = 0; i < zap_reply_frame_count; i++) {
        rc = msg[i].init ();
        errno_assert (rc == 0);
    }

    for (size_t i = 0; i < zap_reply_frame_count; i++) {
        rc = session->read_zap_msg (&msg[i]);
        if (rc == -1) {
            if (errno == EAGAIN) {
                return 1;
            }
            return close_and_return (msg, -1);
        }
        if ((msg[i].flags () & msg_t::more)
            == (i < zap_reply_frame_count - 1 ? 0 : msg_t::more)) {
            session->get_socket ()->event_handshake_failed_protocol (
              session->get_endpoint (), ZMQ_PROTOCOL_ERROR_ZAP_MALFORMED_REPLY);
            errno = EPROTO;
            return close_and_return (msg, -1);
        }
    }

    //  Address delimiter frame
    if (msg[0].size () > 0) {
        //  TODO can a ZAP handler produce such a message at all?
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (), ZMQ_PROTOCOL_ERROR_ZAP_UNSPECIFIED);
        errno = EPROTO;
        return close_and_return (msg, -1);
    }

    //  Version frame
    if (msg[1].size () != zap_version_len
        || memcmp (msg[1].data (), zap_version, zap_version_len)) {
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (), ZMQ_PROTOCOL_ERROR_ZAP_BAD_VERSION);
        errno = EPROTO;
        return close_and_return (msg, -1);
    }

    //  Request id frame
    if (msg[2].size () != id_len || memcmp (msg[2].data (), id, id_len)) {
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (), ZMQ_PROTOCOL_ERROR_ZAP_BAD_REQUEST_ID);
        errno = EPROTO;
        return close_and_return (msg, -1);
    }

    //  Status code frame, only 200, 300, 400 and 500 are valid status codes
    const char *status_code_data = static_cast<const char *> (msg[3].data ());
    if (msg[3].size () != 3 || status_code_data[0] < '2'
        || status_code_data[0] > '5' || status_code_data[1] != '0'
        || status_code_data[2] != '0') {
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (), ZMQ_PROTOCOL_ERROR_ZAP_INVALID_STATUS_CODE);
        errno = EPROTO;
        return close_and_return (msg, -1);
    }

    //  Save status code
    status_code.assign (static_cast<char *> (msg[3].data ()), 3);

    //  Save user id
    set_user_id (msg[5].data (), msg[5].size ());

    //  Process metadata frame
    rc = parse_metadata (static_cast<const unsigned char *> (msg[6].data ()),
                         msg[6].size (), true);

    if (rc != 0) {
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (), ZMQ_PROTOCOL_ERROR_ZAP_INVALID_METADATA);
        errno = EPROTO;
        return close_and_return (msg, -1);
    }

    //  Close all reply frames
    for (size_t i = 0; i < zap_reply_frame_count; i++) {
        const int rc2 = msg[i].close ();
        errno_assert (rc2 == 0);
    }

    handle_zap_status_code ();

    return 0;
}

void zap_client_t::handle_zap_status_code ()
{
    //  we can assume here that status_code is a valid ZAP status code,
    //  i.e. 200, 300, 400 or 500
    int status_code_numeric = 0;
    switch (status_code[0]) {
        case '2':
            return;
        case '3':
            status_code_numeric = 300;
            break;
        case '4':
            status_code_numeric = 400;
            break;
        case '5':
            status_code_numeric = 500;
            break;
    }

    session->get_socket ()->event_handshake_failed_auth (
      session->get_endpoint (), status_code_numeric);
}

zap_client_common_handshake_t::zap_client_common_handshake_t (
  session_base_t *const session_,
  const std::string &peer_address_,
  const options_t &options_,
  state_t zap_reply_ok_state_) :
    mechanism_base_t (session_, options_),
    zap_client_t (session_, peer_address_, options_),
    state (waiting_for_hello),
    _zap_reply_ok_state (zap_reply_ok_state_)
{
}

zmq::mechanism_t::status_t zap_client_common_handshake_t::status () const
{
    if (state == ready)
        return mechanism_t::ready;
    if (state == error_sent)
        return mechanism_t::error;

    return mechanism_t::handshaking;
}

int zap_client_common_handshake_t::zap_msg_available ()
{
    zmq_assert (state == waiting_for_zap_reply);
    return receive_and_process_zap_reply () == -1 ? -1 : 0;
}

void zap_client_common_handshake_t::handle_zap_status_code ()
{
    zap_client_t::handle_zap_status_code ();

    //  we can assume here that status_code is a valid ZAP status code,
    //  i.e. 200, 300, 400 or 500
    switch (status_code[0]) {
        case '2':
            state = _zap_reply_ok_state;
            break;
        case '3':
            //  a 300 error code (temporary failure)
            //  should NOT result in an ERROR message, but instead the
            //  client should be silently disconnected (see CURVEZMQ RFC)
            //  therefore, go immediately to state error_sent
            state = error_sent;
            break;
        default:
            state = sending_error;
    }
}

int zap_client_common_handshake_t::receive_and_process_zap_reply ()
{
    zmq_assert (state == waiting_for_zap_reply);
    return zap_client_t::receive_and_process_zap_reply ();
}
}
