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
#include "err.hpp"
#include "plain_mechanism.hpp"
#include "wire.hpp"

zmq::plain_mechanism_t::plain_mechanism_t (const options_t &options_,
                                           bool as_server_) :
    mechanism_t (options_),
    state (as_server_? waiting_for_hello: sending_hello)
{
}

zmq::plain_mechanism_t::~plain_mechanism_t ()
{
}

int zmq::plain_mechanism_t::next_handshake_message (msg_t *msg_)
{
    int rc = 0;

    switch (state) {
    case sending_hello:
        rc = hello_command (msg_);
        if (rc == 0)
            state = waiting_for_welcome;
        break;
    case sending_welcome:
        rc = welcome_command (msg_);
        if (rc == 0)
            state = waiting_for_initiate;
        break;
    case sending_initiate:
        rc = initiate_command (msg_);
        if (rc == 0)
            state = waiting_for_ready;
        break;
    case sending_ready:
        rc = ready_command (msg_);
        if (rc == 0)
            state = ready;
        break;
    default:
        errno = EAGAIN;
        rc = -1;
    }

    return rc;
}

int zmq::plain_mechanism_t::process_handshake_message (msg_t *msg_)
{
    int rc = 0;

    switch (state) {
    case waiting_for_hello:
        rc = process_hello_command (msg_);
        if (rc == 0)
            state = sending_welcome;
        break;
    case waiting_for_welcome:
        rc = process_welcome_command (msg_);
        if (rc == 0)
            state = sending_initiate;
        break;
    case waiting_for_initiate:
        rc = process_initiate_command (msg_);
        if (rc == 0)
            state = sending_ready;
        break;
    case waiting_for_ready:
        rc = process_ready_command (msg_);
        if (rc == 0)
            state = ready;
        break;
    default:
        errno = EAGAIN;
        rc = -1;
    }

    if (rc == 0) {
        rc = msg_->close ();
        errno_assert (rc == 0);
        rc = msg_->init ();
        errno_assert (rc == 0);
    }

    return 0;
}

bool zmq::plain_mechanism_t::is_handshake_complete () const
{
    return state == ready;
}

int zmq::plain_mechanism_t::hello_command (msg_t *msg_) const
{
    const std::string username = options.plain_username;
    zmq_assert (username.length () < 256);

    const std::string password = options.plain_password;
    zmq_assert (password.length () < 256);

    const size_t command_size = 8 + 1 + username.length () +
        1 + password.length ();

    const int rc = msg_->init_size (command_size);
    errno_assert (rc == 0);

    unsigned char *ptr = static_cast<unsigned char*> (msg_->data ());

    memcpy (ptr, "HELLO   ", 8);
    ptr += 8;
    *ptr++ = static_cast <unsigned char> (username.length ());
    memcpy (ptr, username.c_str (), username.length ());
    ptr += username.length ();
    *ptr++ = static_cast <unsigned char> (password.length ());
    memcpy (ptr, password.c_str (), password.length ());
    ptr += password.length ();

    return 0;
}

int zmq::plain_mechanism_t::process_hello_command (msg_t *msg_)
{
    const unsigned char *ptr = static_cast <unsigned char *> (msg_->data ());
    size_t bytes_left = msg_->size ();

    if (bytes_left < 8 || memcmp (ptr, "HELLO   ", 8)) {
        errno = EPROTO;
        return -1;
    }

    ptr += 8;
    bytes_left -= 8;

    if (bytes_left < 1) {
        errno = EPROTO;
        return -1;
    }

    size_t username_length = static_cast <size_t> (*ptr++);
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

    size_t password_length = static_cast <size_t> (*ptr++);
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

    // TODO: Add user authentication

    return 0;
}

int zmq::plain_mechanism_t::welcome_command (msg_t *msg_) const
{
    const int rc = msg_->init_size (8);
    errno_assert (rc == 0);
    memcpy (msg_->data (), "WELCOME ", 8);
    return 0;
}

int zmq::plain_mechanism_t::process_welcome_command (msg_t *msg_)
{
    const unsigned char *ptr = static_cast <unsigned char *> (msg_->data ());
    size_t bytes_left = msg_->size ();

    if (bytes_left != 8 ||  memcmp (ptr, "WELCOME ", 8)) {
        errno = EPROTO;
        return -1;
    }

    return 0;
}

int zmq::plain_mechanism_t::initiate_command (msg_t *msg_) const
{
    unsigned char * const command_buffer = (unsigned char *) malloc (512);
    alloc_assert (command_buffer);

    unsigned char *ptr = command_buffer;

    //  Add mechanism string
    memcpy (ptr, "INITIATE", 8);
    ptr += 8;

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

int zmq::plain_mechanism_t::process_initiate_command (msg_t *msg_)
{
    const unsigned char *ptr = static_cast <unsigned char *> (msg_->data ());
    size_t bytes_left = msg_->size ();

    if (bytes_left < 8 || memcmp (ptr, "INITIATE", 8)) {
        errno = EPROTO;
        return -1;
    }

    return parse_property_list (ptr + 8, bytes_left - 8);
}

int zmq::plain_mechanism_t::ready_command (msg_t *msg_) const
{
    unsigned char * const command_buffer = (unsigned char *) malloc (512);
    alloc_assert (command_buffer);

    unsigned char *ptr = command_buffer;

    //  Add mechanism string
    memcpy (ptr, "READY   ", 8);
    ptr += 8;

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

int zmq::plain_mechanism_t::process_ready_command (msg_t *msg_)
{
    const unsigned char *ptr = static_cast <unsigned char *> (msg_->data ());
    size_t bytes_left = msg_->size ();

    if (bytes_left < 8 || memcmp (ptr, "READY   ", 8)) {
        errno = EPROTO;
        return -1;
    }

    return parse_property_list (ptr + 8, bytes_left - 8);
}

int zmq::plain_mechanism_t::parse_property_list (const unsigned char *ptr,
    size_t bytes_left)
{
    while (bytes_left > 1) {
        const size_t name_length = static_cast <size_t> (*ptr);
        ptr += 1;
        bytes_left -= 1;

        if (bytes_left < name_length)
            break;
        const std::string name = std::string((const char *) ptr, name_length);
        ptr += name_length;
        bytes_left -= name_length;

        if (bytes_left < 4)
            break;
        const size_t value_length = static_cast <size_t> (get_uint32 (ptr));
        ptr += 4;
        bytes_left -= 4;

        if (bytes_left < value_length)
            break;
        const unsigned char * const value = ptr;
        ptr += value_length;
        bytes_left -= value_length;

        if (name == "Socket-Type") {
            //  TODO: Implement socket type checking
        }
        else
        if (name == "Identity" && options.recv_identity)
            set_peer_identity (value, value_length);
    }

    if (bytes_left > 0) {
        errno = EPROTO;
        return -1;
    }

    return 0;
}
