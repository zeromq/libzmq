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

#include "msg.hpp"
#include "err.hpp"
#include "plain_client.hpp"

zmq::plain_client_t::plain_client_t (const options_t &options_) :
    mechanism_t (options_),
    state (sending_hello)
{
}

zmq::plain_client_t::~plain_client_t ()
{
}

int zmq::plain_client_t::next_handshake_command (msg_t *msg_)
{
    int rc = 0;

    switch (state) {
        case sending_hello:
            rc = produce_hello (msg_);
            if (rc == 0)
                state = waiting_for_welcome;
            break;
        case sending_initiate:
            rc = produce_initiate (msg_);
            if (rc == 0)
                state = waiting_for_ready;
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
        static_cast <unsigned char *> (msg_->data ());
    const size_t data_size = msg_->size ();

    int rc = 0;
    if (data_size >= 8 && !memcmp (cmd_data, "\7WELCOME", 8))
        rc = process_welcome (cmd_data, data_size);
    else
    if (data_size >= 6 && !memcmp (cmd_data, "\5READY", 6))
        rc = process_ready (cmd_data, data_size);
    else
    if (data_size >= 6 && !memcmp (cmd_data, "\5ERROR", 6))
        rc = process_error (cmd_data, data_size);
    else {
        //  Temporary support for security debugging
        puts ("PLAIN I: invalid handshake command");
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
    if (state == ready)
        return mechanism_t::ready;
    else
    if (state == error_command_received)
        return mechanism_t::error;
    else
        return mechanism_t::handshaking;
}

int zmq::plain_client_t::produce_hello (msg_t *msg_) const
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

int zmq::plain_client_t::process_welcome (
        const unsigned char *cmd_data, size_t data_size)
{
    LIBZMQ_UNUSED (cmd_data);

    if (state != waiting_for_welcome) {
        errno = EPROTO;
        return -1;
    }
    if (data_size != 8) {
        errno = EPROTO;
        return -1;
    }
    state = sending_initiate;
    return 0;
}

int zmq::plain_client_t::produce_initiate (msg_t *msg_) const
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

int zmq::plain_client_t::process_ready (
        const unsigned char *cmd_data, size_t data_size)
{
    if (state != waiting_for_ready) {
        errno = EPROTO;
        return -1;
    }
    const int rc = parse_metadata (cmd_data + 6, data_size - 6);
    if (rc == 0)
        state = ready;
    return rc;
}

int zmq::plain_client_t::process_error (
        const unsigned char *cmd_data, size_t data_size)
{
    if (state != waiting_for_welcome && state != waiting_for_ready) {
        errno = EPROTO;
        return -1;
    }
    if (data_size < 7) {
        errno = EPROTO;
        return -1;
    }
    const size_t error_reason_len = static_cast <size_t> (cmd_data [6]);
    if (error_reason_len > data_size - 7) {
        errno = EPROTO;
        return -1;
    }
    state = error_command_received;
    return 0;
}
