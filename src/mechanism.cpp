/*
    Copyright (c) 2007-2015 Contributors as noted in the AUTHORS file

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

void zmq::mechanism_t::set_user_id (const void *data_, size_t size_)
{
    user_id = blob_t (static_cast <const unsigned char*> (data_), size_);
    zap_properties.insert (
        metadata_t::dict_t::value_type (
            "User-Id", std::string ((char *) data_, size_)));
}

zmq::blob_t zmq::mechanism_t::get_user_id () const
{
    return user_id;
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
                                      size_t length_, bool zap_flag)
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
        if (zap_flag)
            zap_properties.insert (
                metadata_t::dict_t::value_type (
                    name, std::string ((char *) value, value_length)));
        else
            zmtp_properties.insert (
                metadata_t::dict_t::value_type (
                    name, std::string ((char *) value, value_length)));
    }
    if (bytes_left > 0) {
        errno = EPROTO;
        return -1;
    }
    return 0;
}

int zmq::mechanism_t::property (const std::string& /* name_ */,
                                const void * /* value_ */, size_t /* length_ */)
{
    //  Default implementation does not check
    //  property values and returns 0 to signal success.
    return 0;
}

bool zmq::mechanism_t::check_socket_type (const std::string& type_) const
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
