/*
    Copyright (c) 2007-2013 Contributors as noted in the AUTHORS file

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "platform.hpp"
#ifdef ZMQ_HAVE_WINDOWS
#include "windows.hpp"
#endif

#include <string.h>
#include <string>

#include "msg.hpp"
#include "session_base.hpp"
#include "err.hpp"
#include "plain_mechanism.hpp"
#include "wire.hpp"

zmq::plain_mechanism_t::plain_mechanism_t (session_base_t *session_,
                                           const std::string &peer_address_,
                                           const options_t &options_) :
    mechanism_t (options_),
    session (session_),
    peer_address (peer_address_),
    expecting_zap_reply (false),
    state (options.as_server? waiting_for_hello: sending_hello)
{
}

zmq::plain_mechanism_t::~plain_mechanism_t ()
{
}

int zmq::plain_mechanism_t::next_handshake_command (msg_t *msg_)
{
    int rc = 0;

    switch (state) {
        case sending_hello:
            rc = produce_hello (msg_);
            if (rc == 0)
                state = waiting_for_welcome;
            break;
        case sending_welcome:
            rc = produce_welcome (msg_);
            if (rc == 0)
                state = waiting_for_initiate;
            break;
        case sending_initiate:
            rc = produce_initiate (msg_);
            if (rc == 0)
                state = waiting_for_ready;
            break;
        case sending_ready:
            rc = produce_ready (msg_);
            if (rc == 0)
                state = ready;
            break;
        default:
            errno = EAGAIN;
            rc = -1;
    }
    return rc;
}

int zmq::plain_mechanism_t::process_handshake_command (msg_t *msg_)
{
    int rc = 0;

    switch (state) {
        case waiting_for_hello:
            rc = process_hello (msg_);
            if (rc == 0)
                state = expecting_zap_reply? waiting_for_zap_reply: sending_welcome;
            break;
        case waiting_for_welcome:
            rc = process_welcome (msg_);
            if (rc == 0)
                state = sending_initiate;
            break;
        case waiting_for_initiate:
            rc = process_initiate (msg_);
            if (rc == 0)
                state = sending_ready;
            break;
        case waiting_for_ready:
            rc = process_ready (msg_);
            if (rc == 0)
                state = ready;
            break;
        default:
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

bool zmq::plain_mechanism_t::is_handshake_complete () const
{
    return state == ready;
}

int zmq::plain_mechanism_t::zap_msg_available ()
{
    if (state != waiting_for_zap_reply) {
        errno = EFSM;
        return -1;
    }
    const int rc = receive_and_process_zap_reply ();
    if (rc == 0)
        state = sending_welcome;
    return rc;
}

int zmq::plain_mechanism_t::produce_hello (msg_t *msg_) const
{
    const std::string username = options.plain_username;
    zmq_assert (username.length () < 256);

    const std::string password = options.plain_password;
    zmq_assert (password.length () < 256);

    const size_t command_size = 6 + 1 + username.length ()
                                  + 1 + password.length ();

    const int rc = msg_->init_size (command_size);
    errno_assert (rc == 0);

    unsigned char *ptr = static_cast <unsigned char *> (msg_->data ());
    memcpy (ptr, "\x05HELLO", 6);
    ptr += 6;

    *ptr++ = static_cast <unsigned char> (username.length ());
    memcpy (ptr, username.c_str (), username.length ());
    ptr += username.length ();

    *ptr++ = static_cast <unsigned char> (password.length ());
    memcpy (ptr, password.c_str (), password.length ());
    ptr += password.length ();

    return 0;
}


int zmq::plain_mechanism_t::process_hello (msg_t *msg_)
{
    const unsigned char *ptr = static_cast <unsigned char *> (msg_->data ());
    size_t bytes_left = msg_->size ();

    if (bytes_left < 6 || memcmp (ptr, "\x05HELLO", 6)) {
        errno = EPROTO;
        return -1;
    }
    ptr += 6;
    bytes_left -= 6;

    if (bytes_left < 1) {
        errno = EPROTO;
        return -1;
    }
    const size_t username_length = static_cast <size_t> (*ptr++);
    bytes_left -= 1;

    if (bytes_left < username_length) {
        errno = EPROTO;
        return -1;
    }
    const std::string username = std::string ((char *) ptr, username_length);
    ptr += username_length;
    bytes_left -= username_length;

    if (bytes_left < 1) {
        errno = EPROTO;
        return -1;
    }
    const size_t password_length = static_cast <size_t> (*ptr++);
    bytes_left -= 1;

    if (bytes_left < password_length) {
        errno = EPROTO;
        return -1;
    }
    const std::string password = std::string ((char *) ptr, password_length);
    ptr += password_length;
    bytes_left -= password_length;

    if (bytes_left > 0) {
        errno = EPROTO;
        return -1;
    }

    //  Use ZAP protocol (RFC 27) to authenticate the user.
    int rc = session->zap_connect ();
    if (rc == 0) {
        send_zap_request (username, password);
        rc = receive_and_process_zap_reply ();
        if (rc != 0) {
            if (errno != EAGAIN)
                return -1;
            expecting_zap_reply = true;
        }
    }

    return 0;
}

int zmq::plain_mechanism_t::produce_welcome (msg_t *msg_) const
{
    const int rc = msg_->init_size (8);
    errno_assert (rc == 0);
    memcpy (msg_->data (), "\x07WELCOME", 8);
    return 0;
}

int zmq::plain_mechanism_t::process_welcome (msg_t *msg_)
{
    const unsigned char *ptr = static_cast <unsigned char *> (msg_->data ());
    size_t bytes_left = msg_->size ();

    if (bytes_left != 8 ||  memcmp (ptr, "\x07WELCOME", 8)) {
        errno = EPROTO;
        return -1;
    }
    return 0;
}

int zmq::plain_mechanism_t::produce_initiate (msg_t *msg_) const
{
    unsigned char * const command_buffer = (unsigned char *) malloc (512);
    alloc_assert (command_buffer);

    unsigned char *ptr = command_buffer;

    //  Add mechanism string
    memcpy (ptr, "\x08INITIATE", 9);
    ptr += 9;

    //  Add socket type property
    const char *socket_type = socket_type_string (options.type);
    ptr += add_property (ptr, "Socket-Type", socket_type, strlen (socket_type));

    //  Add identity property
    if (options.type == ZMQ_REQ
    ||  options.type == ZMQ_DEALER
    ||  options.type == ZMQ_ROUTER) {
        ptr += add_property (ptr, "Identity",
            options.identity, options.identity_size);
    }

    const size_t command_size = ptr - command_buffer;
    const int rc = msg_->init_size (command_size);
    errno_assert (rc == 0);
    memcpy (msg_->data (), command_buffer, command_size);
    free (command_buffer);

    return 0;
}

int zmq::plain_mechanism_t::process_initiate (msg_t *msg_)
{
    const unsigned char *ptr = static_cast <unsigned char *> (msg_->data ());
    size_t bytes_left = msg_->size ();

    if (bytes_left < 9 || memcmp (ptr, "\x08INITIATE", 9)) {
        errno = EPROTO;
        return -1;
    }
    ptr += 9;
    bytes_left -= 9;
    return parse_metadata (ptr, bytes_left);
}

int zmq::plain_mechanism_t::produce_ready (msg_t *msg_) const
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
    ||  options.type == ZMQ_ROUTER) {
        ptr += add_property (ptr, "Identity",
            options.identity, options.identity_size);
    }

    const size_t command_size = ptr - command_buffer;
    const int rc = msg_->init_size (command_size);
    errno_assert (rc == 0);
    memcpy (msg_->data (), command_buffer, command_size);
    free (command_buffer);

    return 0;
}

int zmq::plain_mechanism_t::process_ready (msg_t *msg_)
{
    const unsigned char *ptr = static_cast <unsigned char *> (msg_->data ());
    size_t bytes_left = msg_->size ();

    if (bytes_left < 6 || memcmp (ptr, "\x05READY", 6)) {
        errno = EPROTO;
        return -1;
    }
    ptr += 6;
    bytes_left -= 6;
    return parse_metadata (ptr, bytes_left);
}

void zmq::plain_mechanism_t::send_zap_request (const std::string &username,
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

int zmq::plain_mechanism_t::receive_and_process_zap_reply ()
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
            errno = EPROTO;
            rc = -1;
            break;
        }
    }

    if (rc != 0)
        goto error;

    //  Address delimiter frame
    if (msg [0].size () > 0) {
        rc = -1;
        errno = EPROTO;
        goto error;
    }

    //  Version frame
    if (msg [1].size () != 3 || memcmp (msg [1].data (), "1.0", 3)) {
        rc = -1;
        errno = EPROTO;
        goto error;
    }

    //  Request id frame
    if (msg [2].size () != 1 || memcmp (msg [2].data (), "1", 1)) {
        rc = -1;
        errno = EPROTO;
        goto error;
    }

    //  Status code frame
    if (msg [3].size () != 3 || memcmp (msg [3].data (), "200", 3)) {
        rc = -1;
        errno = EACCES;
        goto error;
    }

    //  Process metadata frame
    rc = parse_metadata (static_cast <const unsigned char*> (msg [6].data ()),
                         msg [6].size ());

error:
    for (int i = 0; i < 7; i++) {
        const int rc2 = msg [i].close ();
        errno_assert (rc2 == 0);
    }

    return rc;
}
