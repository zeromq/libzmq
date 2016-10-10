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

#include <string>

#include "msg.hpp"
#include "session_base.hpp"
#include "err.hpp"
#include "plain_server.hpp"
#include "wire.hpp"

zmq::plain_server_t::plain_server_t (session_base_t *session_,
                                     const std::string &peer_address_,
                                     const options_t &options_) :
    mechanism_t (options_),
    session (session_),
    peer_address (peer_address_),
    state (waiting_for_hello)
{
}

zmq::plain_server_t::~plain_server_t ()
{
}

int zmq::plain_server_t::next_handshake_command (msg_t *msg_)
{
    int rc = 0;

    switch (state) {
        case sending_welcome:
            rc = produce_welcome (msg_);
            if (rc == 0)
                state = waiting_for_initiate;
            break;
        case sending_ready:
            rc = produce_ready (msg_);
            if (rc == 0)
                state = ready;
            break;
        case sending_error:
            rc = produce_error (msg_);
            if (rc == 0)
                state = error_command_sent;
            break;
        default:
            errno = EAGAIN;
            rc = -1;
    }
    return rc;
}

int zmq::plain_server_t::process_handshake_command (msg_t *msg_)
{
    int rc = 0;

    switch (state) {
        case waiting_for_hello:
            rc = process_hello (msg_);
            break;
        case waiting_for_initiate:
            rc = process_initiate (msg_);
            break;
        default:
            //  Temporary support for security debugging
            puts ("PLAIN I: invalid handshake command");
            errno = EPROTO;
            rc = -1;
            break;
    }
    if (rc == 0) {
        rc = msg_->close ();
        errno_assert (rc == 0);
        rc = msg_->init ();
        errno_assert (rc == 0);
    }
    return rc;
}

zmq::mechanism_t::status_t zmq::plain_server_t::status () const
{
    if (state == ready)
        return mechanism_t::ready;
    else
    if (state == error_command_sent)
        return mechanism_t::error;
    else
        return mechanism_t::handshaking;
}

int zmq::plain_server_t::zap_msg_available ()
{
    if (state != waiting_for_zap_reply) {
        errno = EFSM;
        return -1;
    }
    const int rc = receive_and_process_zap_reply ();
    if (rc == 0)
        state = status_code == "200"
            ? sending_welcome
            : sending_error;
    return rc;
}

int zmq::plain_server_t::process_hello (msg_t *msg_)
{
    const unsigned char *ptr = static_cast <unsigned char *> (msg_->data ());
    size_t bytes_left = msg_->size ();

    if (bytes_left < 6 || memcmp (ptr, "\x05HELLO", 6)) {
        //  Temporary support for security debugging
        puts ("PLAIN I: invalid PLAIN client, did not send HELLO");
        errno = EPROTO;
        return -1;
    }
    ptr += 6;
    bytes_left -= 6;

    if (bytes_left < 1) {
        //  Temporary support for security debugging
        puts ("PLAIN I: invalid PLAIN client, did not send username");
        errno = EPROTO;
        return -1;
    }
    const size_t username_length = static_cast <size_t> (*ptr++);
    bytes_left -= 1;

    if (bytes_left < username_length) {
        //  Temporary support for security debugging
        puts ("PLAIN I: invalid PLAIN client, sent malformed username");
        errno = EPROTO;
        return -1;
    }
    const std::string username = std::string ((char *) ptr, username_length);
    ptr += username_length;
    bytes_left -= username_length;
    if (bytes_left < 1) {
        //  Temporary support for security debugging
        puts ("PLAIN I: invalid PLAIN client, did not send password");
        errno = EPROTO;
        return -1;
    }

    const size_t password_length = static_cast <size_t> (*ptr++);
    bytes_left -= 1;
    if (bytes_left < password_length) {
        //  Temporary support for security debugging
        puts ("PLAIN I: invalid PLAIN client, sent malformed password");
        errno = EPROTO;
        return -1;
    }

    const std::string password = std::string ((char *) ptr, password_length);
    ptr += password_length;
    bytes_left -= password_length;
    if (bytes_left > 0) {
        //  Temporary support for security debugging
        puts ("PLAIN I: invalid PLAIN client, sent extraneous data");
        errno = EPROTO;
        return -1;
    }

    //  Use ZAP protocol (RFC 27) to authenticate the user.
    int rc = session->zap_connect ();
    if (rc == 0) {
        send_zap_request (username, password);
        rc = receive_and_process_zap_reply ();
        if (rc == 0)
            state = status_code == "200"
                ? sending_welcome
                : sending_error;
        else
        if (errno == EAGAIN)
            state = waiting_for_zap_reply;
        else
            return -1;
    }
    else
        state = sending_welcome;

    return 0;
}

int zmq::plain_server_t::produce_welcome (msg_t *msg_) const
{
    const int rc = msg_->init_size (8);
    errno_assert (rc == 0);
    memcpy (msg_->data (), "\x07WELCOME", 8);
    return 0;
}

int zmq::plain_server_t::process_initiate (msg_t *msg_)
{
    const unsigned char *ptr = static_cast <unsigned char *> (msg_->data ());
    const size_t bytes_left = msg_->size ();

    if (bytes_left < 9 || memcmp (ptr, "\x08INITIATE", 9)) {
        //  Temporary support for security debugging
        puts ("PLAIN I: invalid PLAIN client, did not send INITIATE");
        errno = EPROTO;
        return -1;
    }
    const int rc = parse_metadata (ptr + 9, bytes_left - 9);
    if (rc == 0)
        state = sending_ready;
    return rc;
}

int zmq::plain_server_t::produce_ready (msg_t *msg_) const
{
    unsigned char * const command_buffer = (unsigned char *) malloc (512);
    alloc_assert (command_buffer);

    unsigned char *ptr = command_buffer;

    //  Add command name
    memcpy (ptr, "\x05READY", 6);
    ptr += 6;

    //  Add socket type property
    const char *socket_type = socket_type_string (options.type);
    ptr += add_property (ptr, "Socket-Type", socket_type, strlen (socket_type));

    //  Add identity property
    if (options.type == ZMQ_REQ
    ||  options.type == ZMQ_DEALER
    ||  options.type == ZMQ_ROUTER)
        ptr += add_property (
            ptr, "Identity", options.identity, options.identity_size);

    const size_t command_size = ptr - command_buffer;
    const int rc = msg_->init_size (command_size);
    errno_assert (rc == 0);
    memcpy (msg_->data (), command_buffer, command_size);
    free (command_buffer);

    return 0;
}

int zmq::plain_server_t::produce_error (msg_t *msg_) const
{
    zmq_assert (status_code.length () == 3);
    const int rc = msg_->init_size (6 + 1 + status_code.length ());
    zmq_assert (rc == 0);
    char *msg_data = static_cast <char *> (msg_->data ());
    memcpy (msg_data, "\5ERROR", 6);
    msg_data [6] = (char) status_code.length ();
    memcpy (msg_data + 7, status_code.c_str (), status_code.length ());
    return 0;
}

void zmq::plain_server_t::send_zap_request (const std::string &username,
                                            const std::string &password)
{
    int rc;
    msg_t msg;

    //  Address delimiter frame
    rc = msg.init ();
    errno_assert (rc == 0);
    msg.set_flags (msg_t::more);
    rc = session->write_zap_msg (&msg);
    errno_assert (rc == 0);

    //  Version frame
    rc = msg.init_size (3);
    errno_assert (rc == 0);
    memcpy (msg.data (), "1.0", 3);
    msg.set_flags (msg_t::more);
    rc = session->write_zap_msg (&msg);
    errno_assert (rc == 0);

    //  Request id frame
    rc = msg.init_size (1);
    errno_assert (rc == 0);
    memcpy (msg.data (), "1", 1);
    msg.set_flags (msg_t::more);
    rc = session->write_zap_msg (&msg);
    errno_assert (rc == 0);

    //  Domain frame
    rc = msg.init_size (options.zap_domain.length ());
    errno_assert (rc == 0);
    memcpy (msg.data (), options.zap_domain.c_str (), options.zap_domain.length ());
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

    //  Identity frame
    rc = msg.init_size (options.identity_size);
    errno_assert (rc == 0);
    memcpy (msg.data (), options.identity, options.identity_size);
    msg.set_flags (msg_t::more);
    rc = session->write_zap_msg (&msg);
    errno_assert (rc == 0);

    //  Mechanism frame
    rc = msg.init_size (5);
    errno_assert (rc == 0);
    memcpy (msg.data (), "PLAIN", 5);
    msg.set_flags (msg_t::more);
    rc = session->write_zap_msg (&msg);
    errno_assert (rc == 0);

    //  Username frame
    rc = msg.init_size (username.length ());
    errno_assert (rc == 0);
    memcpy (msg.data (), username.c_str (), username.length ());
    msg.set_flags (msg_t::more);
    rc = session->write_zap_msg (&msg);
    errno_assert (rc == 0);

    //  Password frame
    rc = msg.init_size (password.length ());
    errno_assert (rc == 0);
    memcpy (msg.data (), password.c_str (), password.length ());
    rc = session->write_zap_msg (&msg);
    errno_assert (rc == 0);
}

int zmq::plain_server_t::receive_and_process_zap_reply ()
{
    int rc = 0;
    msg_t msg [7];  //  ZAP reply consists of 7 frames

    //  Initialize all reply frames
    for (int i = 0; i < 7; i++) {
        rc = msg [i].init ();
        errno_assert (rc == 0);
    }

    for (int i = 0; i < 7; i++) {
        rc = session->read_zap_msg (&msg [i]);
        if (rc == -1)
            break;
        if ((msg [i].flags () & msg_t::more) == (i < 6? 0: msg_t::more)) {
            //  Temporary support for security debugging
            puts ("PLAIN I: ZAP handler sent incomplete reply message");
            errno = EPROTO;
            rc = -1;
            break;
        }
    }

    if (rc != 0)
        goto error;

    //  Address delimiter frame
    if (msg [0].size () > 0) {
        //  Temporary support for security debugging
        puts ("PLAIN I: ZAP handler sent malformed reply message");
        errno = EPROTO;
        rc = -1;
        goto error;
    }

    //  Version frame
    if (msg [1].size () != 3 || memcmp (msg [1].data (), "1.0", 3)) {
        //  Temporary support for security debugging
        puts ("PLAIN I: ZAP handler sent bad version number");
        errno = EPROTO;
        rc = -1;
        goto error;
    }

    //  Request id frame
    if (msg [2].size () != 1 || memcmp (msg [2].data (), "1", 1)) {
        //  Temporary support for security debugging
        puts ("PLAIN I: ZAP handler sent bad request ID");
        rc = -1;
        errno = EPROTO;
        goto error;
    }

    //  Status code frame
    if (msg [3].size () != 3) {
        //  Temporary support for security debugging
        puts ("PLAIN I: ZAP handler rejected client authentication");
        errno = EACCES;
        rc = -1;
        goto error;
    }

    //  Save status code
    status_code.assign (static_cast <char *> (msg [3].data ()), 3);

    //  Save user id
    set_user_id (msg [5].data (), msg [5].size ());

    //  Process metadata frame
    rc = parse_metadata (static_cast <const unsigned char*> (msg [6].data ()),
                         msg [6].size (), true);

error:
    for (int i = 0; i < 7; i++) {
        const int rc2 = msg [i].close ();
        errno_assert (rc2 == 0);
    }

    return rc;
}
