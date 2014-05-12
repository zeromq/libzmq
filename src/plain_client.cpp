/*
    Copyright (c) 2007-2014 Contributors as noted in the AUTHORS file

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
    int rc = 0;

    switch (state) {
        case waiting_for_welcome:
            rc = process_welcome (msg_);
            if (rc == 0)
                state = sending_initiate;
            break;
        case waiting_for_ready:
            rc = process_ready (msg_);
            if (rc == 0)
                state = ready;
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

zmq::mechanism_t::status_t zmq::plain_client_t::status () const
{
    return state == ready? mechanism_t::ready: mechanism_t::handshaking;
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

int zmq::plain_client_t::process_welcome (msg_t *msg_)
{
    const unsigned char *ptr = static_cast <unsigned char *> (msg_->data ());
    const size_t bytes_left = msg_->size ();

    if (bytes_left != 8 ||  memcmp (ptr, "\x07WELCOME", 8)) {
        //  Temporary support for security debugging
        puts ("PLAIN I: invalid PLAIN client, did not send WELCOME");
        errno = EPROTO;
        return -1;
    }
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

int zmq::plain_client_t::process_ready (msg_t *msg_)
{
    const unsigned char *ptr = static_cast <unsigned char *> (msg_->data ());
    const size_t bytes_left = msg_->size ();

    if (bytes_left < 6 || memcmp (ptr, "\x05READY", 6)) {
        //  Temporary support for security debugging
        puts ("PLAIN I: invalid PLAIN client, did not send READY");
        errno = EPROTO;
        return -1;
    }
    return parse_metadata (ptr + 6, bytes_left - 6);
}
