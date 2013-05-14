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

#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include "err.hpp"
#include "msg.hpp"
#include "wire.hpp"
#include "null_mechanism.hpp"

zmq::null_mechanism_t::null_mechanism_t (const options_t &options_) : mechanism_t (options_),
  ready_command_sent (false),
  ready_command_received (false)
{
}

zmq::null_mechanism_t::~null_mechanism_t ()
{
}

int zmq::null_mechanism_t::next_handshake_message (msg_t *msg_)
{
    if (ready_command_sent) {
        errno = EAGAIN;
        return -1;
    }

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

    ready_command_sent = true;

    return 0;
}

int zmq::null_mechanism_t::process_handshake_message (msg_t *msg_)
{
    if (ready_command_received) {
        errno = EPROTO;
        return -1;
    }

    const unsigned char *ptr =
        static_cast <unsigned char *> (msg_->data ());
    size_t bytes_left = msg_->size ();

    if (bytes_left < 8 || memcmp (ptr, "READY   ", 8)) {
        errno = EPROTO;
        return -1;
    }

    ptr += 8;
    bytes_left -= 8;

    //  Parse the property list
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

    int rc = msg_->close ();
    errno_assert (rc == 0);
    rc = msg_->init ();
    errno_assert (rc == 0);

    ready_command_received = true;

    return 0;
}

bool zmq::null_mechanism_t::is_handshake_complete () const
{
    return ready_command_received && ready_command_sent;
}
