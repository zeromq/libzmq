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

#include <string.h>

#include "mechanism.hpp"
#include "options.hpp"
#include "msg.hpp"
#include "err.hpp"
#include "wire.hpp"

zmq::mechanism_t::mechanism_t (const options_t &options_) :
    options (options_)
{
}

zmq::mechanism_t::~mechanism_t ()
{
}

void zmq::mechanism_t::set_peer_identity (const void *id_ptr, size_t id_size)
{
    identity = blob_t (static_cast <const unsigned char*> (id_ptr), id_size);
}

void zmq::mechanism_t::peer_identity (msg_t *msg_)
{
    const int rc = msg_->init_size (identity.size ());
    errno_assert (rc == 0);
    memcpy (msg_->data (), identity.data (), identity.size ());
    msg_->set_flags (msg_t::identity);
}

const char *zmq::mechanism_t::socket_type_string (int socket_type) const
{
    static const char *names [] = {"PAIR", "PUB", "SUB", "REQ", "REP",
                                   "DEALER", "ROUTER", "PULL", "PUSH",
                                   "XPUB", "XSUB", "STREAM"};
    zmq_assert (socket_type >= 0 && socket_type <= 10);
    return names [socket_type];
}

size_t zmq::mechanism_t::add_property (unsigned char *ptr, const char *name,
    const void *value, size_t value_len) const
{
    const size_t name_len = strlen (name);
    zmq_assert (name_len <= 255);
    *ptr++ = static_cast <unsigned char> (name_len);
    memcpy (ptr, name, name_len);
    ptr += name_len;
    zmq_assert (value_len <= 0x7FFFFFFF);
    put_uint32 (ptr, static_cast <uint32_t> (value_len));
    ptr += 4;
    memcpy (ptr, value, value_len);

    return 1 + name_len + 4 + value_len;
}

int zmq::mechanism_t::parse_metadata (const unsigned char *ptr_,
                                      size_t length_)
{
    size_t bytes_left = length_;

    while (bytes_left > 1) {
        const size_t name_length = static_cast <size_t> (*ptr_);
        ptr_ += 1;
        bytes_left -= 1;
        if (bytes_left < name_length)
            break;

        const std::string name = std::string ((char *) ptr_, name_length);
        ptr_ += name_length;
        bytes_left -= name_length;
        if (bytes_left < 4)
            break;

        const size_t value_length = static_cast <size_t> (get_uint32 (ptr_));
        ptr_ += 4;
        bytes_left -= 4;
        if (bytes_left < value_length)
            break;

        const uint8_t *value = ptr_;
        ptr_ += value_length;
        bytes_left -= value_length;

        if (name == "Identity" && options.recv_identity)
            set_peer_identity (value, value_length);
        else
        if (name == "Socket-Type") {
            const std::string socket_type ((char *) value, value_length);
            if (!check_socket_type (socket_type)) {
                errno = EINVAL;
                return -1;
            }
        }
        else {
            const int rc = property (name, value, value_length);
            if (rc == -1)
                return -1;
        }
    }
    if (bytes_left > 0) {
        errno = EPROTO;
        return -1;
    }
    return 0;
}

int zmq::mechanism_t::property (const std::string name_,
                                const void *value_, size_t length_)
{
    //  Default implementation does not check
    //  property values and returns 0 to signal success.
    return 0;
}

bool zmq::mechanism_t::check_socket_type (const std::string type_) const
{
    switch (options.type) {
        case ZMQ_REQ:
            return type_ == "REP" || type_ == "ROUTER";
        case ZMQ_REP:
            return type_ == "REQ" || type_ == "DEALER";
        case ZMQ_DEALER:
            return type_ == "REP" || type_ == "DEALER" || type_ == "ROUTER";
        case ZMQ_ROUTER:
            return type_ == "REQ" || type_ == "DEALER" || type_ == "ROUTER";
        case ZMQ_PUSH:
            return type_ == "PULL";
        case ZMQ_PULL:
            return type_ == "PUSH";
        case ZMQ_PUB:
            return type_ == "SUB" || type_ == "XSUB";
        case ZMQ_SUB:
            return type_ == "PUB" || type_ == "XPUB";
        case ZMQ_XPUB:
            return type_ == "SUB" || type_ == "XSUB";
        case ZMQ_XSUB:
            return type_ == "PUB" || type_ == "XPUB";
        case ZMQ_PAIR:
            return type_ == "PAIR";
        default:
            break;
    }
    return false;
}
