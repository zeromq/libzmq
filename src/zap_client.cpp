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
zap_client_t::zap_client_t (session_base_t *const session_,
                            const std::string &peer_address_,
                            const options_t &options_) :
    mechanism_t (options_),
    session (session_),
    peer_address (peer_address_)
{
}

int zap_client_t::send_zap_request (const char *mechanism,
                                    size_t mechanism_length,
                                    const uint8_t *credentials,
                                    size_t credentials_size)
{
    return send_zap_request (mechanism, mechanism_length, &credentials,
                             &credentials_size, 1);
}

int zap_client_t::send_zap_request (const char *mechanism,
                                    size_t mechanism_length,
                                    const uint8_t **credentials,
                                    size_t *credentials_sizes,
                                    size_t credentials_count)
{
    // TODO  I don't think the rc can be -1 anywhere below.
    // It might only be -1 if the HWM was exceeded, but on the ZAP socket,
    // the HWM is disabled. They should be changed to zmq_assert (rc == 0);
    // The method's return type can be changed to void then.

    int rc;
    msg_t msg;

    //  Address delimiter frame
    rc = msg.init ();
    errno_assert (rc == 0);
    msg.set_flags (msg_t::more);
    rc = session->write_zap_msg (&msg);
    if (rc != 0)
        return close_and_return (&msg, -1);

    //  Version frame
    rc = msg.init_size (3);
    errno_assert (rc == 0);
    memcpy (msg.data (), "1.0", 3);
    msg.set_flags (msg_t::more);
    rc = session->write_zap_msg (&msg);
    if (rc != 0)
        return close_and_return (&msg, -1);

    //  Request ID frame
    rc = msg.init_size (1);
    errno_assert (rc == 0);
    memcpy (msg.data (), "1", 1);
    msg.set_flags (msg_t::more);
    rc = session->write_zap_msg (&msg);
    if (rc != 0)
        return close_and_return (&msg, -1);

    //  Domain frame
    rc = msg.init_size (options.zap_domain.length ());
    errno_assert (rc == 0);
    memcpy (msg.data (), options.zap_domain.c_str (),
            options.zap_domain.length ());
    msg.set_flags (msg_t::more);
    rc = session->write_zap_msg (&msg);
    if (rc != 0)
        return close_and_return (&msg, -1);

    //  Address frame
    rc = msg.init_size (peer_address.length ());
    errno_assert (rc == 0);
    memcpy (msg.data (), peer_address.c_str (), peer_address.length ());
    msg.set_flags (msg_t::more);
    rc = session->write_zap_msg (&msg);
    if (rc != 0)
        return close_and_return (&msg, -1);

    //  Identity frame
    rc = msg.init_size (options.identity_size);
    errno_assert (rc == 0);
    memcpy (msg.data (), options.identity, options.identity_size);
    msg.set_flags (msg_t::more);
    rc = session->write_zap_msg (&msg);
    if (rc != 0)
        return close_and_return (&msg, -1);

    //  Mechanism frame
    rc = msg.init_size (mechanism_length);
    errno_assert (rc == 0);
    memcpy (msg.data (), mechanism, mechanism_length);
    if (credentials_count)
        msg.set_flags (msg_t::more);
    rc = session->write_zap_msg (&msg);
    if (rc != 0)
        return close_and_return (&msg, -1);

    //  Credentials frames
    for (size_t i = 0; i < credentials_count; ++i) {
        rc = msg.init_size (credentials_sizes[i]);
        errno_assert (rc == 0);
        if (i < credentials_count - 1)
            msg.set_flags (msg_t::more);
        memcpy (msg.data (), credentials[i], credentials_sizes[i]);
        rc = session->write_zap_msg (&msg);
        if (rc != 0)
            return close_and_return (&msg, -1);
    }

    return 0;
}

int zap_client_t::receive_and_process_zap_reply ()
{
    int rc = 0;
    msg_t msg[7]; //  ZAP reply consists of 7 frames

    //  Initialize all reply frames
    for (int i = 0; i < 7; i++) {
        rc = msg[i].init ();
        errno_assert (rc == 0);
    }

    for (int i = 0; i < 7; i++) {
        rc = session->read_zap_msg (&msg[i]);
        if (rc == -1) {
            if (errno == EAGAIN) {
                return 1;
            }
            return close_and_return (msg, -1);
        }
        if ((msg[i].flags () & msg_t::more) == (i < 6 ? 0 : msg_t::more)) {
            // CURVE I : ZAP handler sent incomplete reply message
            errno = EPROTO;
            return close_and_return (msg, -1);
        }
    }

    //  Address delimiter frame
    if (msg[0].size () > 0) {
        // CURVE I: ZAP handler sent malformed reply message
        errno = EPROTO;
        return close_and_return (msg, -1);
    }

    //  Version frame
    if (msg[1].size () != 3 || memcmp (msg[1].data (), "1.0", 3)) {
        // CURVE I: ZAP handler sent bad version number
        errno = EPROTO;
        return close_and_return (msg, -1);
    }

    //  Request id frame
    if (msg[2].size () != 1 || memcmp (msg[2].data (), "1", 1)) {
        // CURVE I: ZAP handler sent bad request ID
        errno = EPROTO;
        return close_and_return (msg, -1);
    }

    //  Status code frame, only 200, 300, 400 and 500 are valid status codes
    char *status_code_data = static_cast<char *> (msg[3].data ());
    if (msg[3].size () != 3 || status_code_data[0] < '2'
        || status_code_data[0] > '5' || status_code_data[1] != '0'
        || status_code_data[2] != '0') {
        // CURVE I: ZAP handler sent invalid status code
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
        return close_and_return (msg, -1);
    }

    //  Close all reply frames
    for (int i = 0; i < 7; i++) {
        const int rc2 = msg[i].close ();
        errno_assert (rc2 == 0);
    }

    handle_zap_status_code ();

    return 0;
}

zap_client_common_handshake_t::zap_client_common_handshake_t (
  session_base_t *const session_,
  const std::string &peer_address_,
  const options_t &options_,
  state_t zap_reply_ok_state_) :
    mechanism_t (options_),
    zap_client_t (session_, peer_address_, options_),
    state (waiting_for_hello),
    current_error_detail (no_detail),
    zap_reply_ok_state (zap_reply_ok_state_)
{
}

zmq::mechanism_t::status_t zap_client_common_handshake_t::status () const
{
    if (state == ready)
        return mechanism_t::ready;
    else if (state == error_sent)
        return mechanism_t::error;
    else
        return mechanism_t::handshaking;
}

int zap_client_common_handshake_t::zap_msg_available ()
{
    //  TODO I don't think that it is possible that this is called in any
    //  state other than expect_zap_reply. It should be changed to
    //  zmq_assert (state == expect_zap_reply);
    if (state != waiting_for_zap_reply) {
        errno = EFSM;
        return -1;
    }
    return receive_and_process_zap_reply () == -1 ? -1 : 0;
}

void zap_client_common_handshake_t::handle_zap_status_code ()
{
    //  we can assume here that status_code is a valid ZAP status code,
    //  i.e. 200, 300, 400 or 500
    if (status_code[0] == '2') {
        state = zap_reply_ok_state;
    } else {
        state = sending_error;

        int err = 0;
        switch (status_code[0]) {
            case '3':
                err = EAGAIN;
                break;
            case '4':
                err = EACCES;
                break;
            case '5':
                err = EFAULT;
                break;
        }
        //  TODO use event_handshake_failed_zap here? but this is not a ZAP
        //  protocol error

        session->get_socket ()->event_handshake_failed_no_detail (
          session->get_endpoint (), err);
    }
}

mechanism_t::error_detail_t zap_client_common_handshake_t::error_detail () const
{
    return current_error_detail;
}

int zap_client_common_handshake_t::receive_and_process_zap_reply ()
{
    int rc = zap_client_t::receive_and_process_zap_reply ();
    switch (rc) {
        case -1:
            if (errno == EPROTO)
                current_error_detail = mechanism_t::zap;
            break;
        case 1:
            // TODO shouldn't the state already be this?
            state = waiting_for_zap_reply;
            break;
        case 0:
            break;
    }
    return rc;
}
}
