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
#include <string.h>
#include <limits.h>

#include "mechanism.hpp"
#include "options.hpp"
#include "msg.hpp"
#include "err.hpp"
#include "wire.hpp"
#include "session_base.hpp"

zmq::mechanism_t::mechanism_t (const options_t &options_) : options (options_)
{
}

zmq::mechanism_t::~mechanism_t ()
{
}

void zmq::mechanism_t::set_peer_routing_id (const void *id_ptr_,
                                            size_t id_size_)
{
    _routing_id.set (static_cast<const unsigned char *> (id_ptr_), id_size_);
}

void zmq::mechanism_t::peer_routing_id (msg_t *msg_)
{
    const int rc = msg_->init_size (_routing_id.size ());
    errno_assert (rc == 0);
    memcpy (msg_->data (), _routing_id.data (), _routing_id.size ());
    msg_->set_flags (msg_t::routing_id);
}

void zmq::mechanism_t::set_user_id (const void *user_id_, size_t size_)
{
    _user_id.set (static_cast<const unsigned char *> (user_id_), size_);
    _zap_properties.ZMQ_MAP_INSERT_OR_EMPLACE (
      std::string (ZMQ_MSG_PROPERTY_USER_ID),
      std::string (reinterpret_cast<const char *> (user_id_), size_));
}

const zmq::blob_t &zmq::mechanism_t::get_user_id () const
{
    return _user_id;
}

const char socket_type_pair[] = "PAIR";
const char socket_type_pub[] = "PUB";
const char socket_type_sub[] = "SUB";
const char socket_type_req[] = "REQ";
const char socket_type_rep[] = "REP";
const char socket_type_dealer[] = "DEALER";
const char socket_type_router[] = "ROUTER";
const char socket_type_pull[] = "PULL";
const char socket_type_push[] = "PUSH";
const char socket_type_xpub[] = "XPUB";
const char socket_type_xsub[] = "XSUB";
const char socket_type_stream[] = "STREAM";
#ifdef ZMQ_BUILD_DRAFT_API
const char socket_type_server[] = "SERVER";
const char socket_type_client[] = "CLIENT";
const char socket_type_radio[] = "RADIO";
const char socket_type_dish[] = "DISH";
const char socket_type_gather[] = "GATHER";
const char socket_type_scatter[] = "SCATTER";
const char socket_type_dgram[] = "DGRAM";
const char socket_type_peer[] = "PEER";
const char socket_type_channel[] = "CHANNEL";
#endif

const char *zmq::mechanism_t::socket_type_string (int socket_type_)
{
    // TODO the order must of the names must correspond to the values resp. order of ZMQ_* socket type definitions in zmq.h!
    static const char *names[] = {socket_type_pair,   socket_type_pub,
                                  socket_type_sub,    socket_type_req,
                                  socket_type_rep,    socket_type_dealer,
                                  socket_type_router, socket_type_pull,
                                  socket_type_push,   socket_type_xpub,
                                  socket_type_xsub,   socket_type_stream,
#ifdef ZMQ_BUILD_DRAFT_API
                                  socket_type_server, socket_type_client,
                                  socket_type_radio,  socket_type_dish,
                                  socket_type_gather, socket_type_scatter,
                                  socket_type_dgram,  socket_type_peer,
                                  socket_type_channel
#endif
    };
    static const size_t names_count = sizeof (names) / sizeof (names[0]);
    zmq_assert (socket_type_ >= 0
                && socket_type_ < static_cast<int> (names_count));
    return names[socket_type_];
}

const size_t name_len_size = sizeof (unsigned char);
const size_t value_len_size = sizeof (uint32_t);

static size_t property_len (size_t name_len_, size_t value_len_)
{
    return name_len_size + name_len_ + value_len_size + value_len_;
}

static size_t name_len (const char *name_)
{
    const size_t name_len = strlen (name_);
    zmq_assert (name_len <= UCHAR_MAX);
    return name_len;
}

size_t zmq::mechanism_t::add_property (unsigned char *ptr_,
                                       size_t ptr_capacity_,
                                       const char *name_,
                                       const void *value_,
                                       size_t value_len_)
{
    const size_t name_len = ::name_len (name_);
    const size_t total_len = ::property_len (name_len, value_len_);
    zmq_assert (total_len <= ptr_capacity_);

    *ptr_ = static_cast<unsigned char> (name_len);
    ptr_ += name_len_size;
    memcpy (ptr_, name_, name_len);
    ptr_ += name_len;
    zmq_assert (value_len_ <= 0x7FFFFFFF);
    put_uint32 (ptr_, static_cast<uint32_t> (value_len_));
    ptr_ += value_len_size;
    memcpy (ptr_, value_, value_len_);

    return total_len;
}

size_t zmq::mechanism_t::property_len (const char *name_, size_t value_len_)
{
    return ::property_len (name_len (name_), value_len_);
}

#define ZMTP_PROPERTY_SOCKET_TYPE "Socket-Type"
#define ZMTP_PROPERTY_IDENTITY "Identity"

size_t zmq::mechanism_t::add_basic_properties (unsigned char *ptr_,
                                               size_t ptr_capacity_) const
{
    unsigned char *ptr = ptr_;

    //  Add socket type property
    const char *socket_type = socket_type_string (options.type);
    ptr += add_property (ptr, ptr_capacity_, ZMTP_PROPERTY_SOCKET_TYPE,
                         socket_type, strlen (socket_type));

    //  Add identity (aka routing id) property
    if (options.type == ZMQ_REQ || options.type == ZMQ_DEALER
        || options.type == ZMQ_ROUTER) {
        ptr += add_property (ptr, ptr_capacity_ - (ptr - ptr_),
                             ZMTP_PROPERTY_IDENTITY, options.routing_id,
                             options.routing_id_size);
    }


    for (std::map<std::string, std::string>::const_iterator
           it = options.app_metadata.begin (),
           end = options.app_metadata.end ();
         it != end; ++it) {
        ptr +=
          add_property (ptr, ptr_capacity_ - (ptr - ptr_), it->first.c_str (),
                        it->second.c_str (), strlen (it->second.c_str ()));
    }

    return ptr - ptr_;
}

size_t zmq::mechanism_t::basic_properties_len () const
{
    const char *socket_type = socket_type_string (options.type);
    size_t meta_len = 0;

    for (std::map<std::string, std::string>::const_iterator
           it = options.app_metadata.begin (),
           end = options.app_metadata.end ();
         it != end; ++it) {
        meta_len +=
          property_len (it->first.c_str (), strlen (it->second.c_str ()));
    }

    return property_len (ZMTP_PROPERTY_SOCKET_TYPE, strlen (socket_type))
           + meta_len
           + ((options.type == ZMQ_REQ || options.type == ZMQ_DEALER
               || options.type == ZMQ_ROUTER)
                ? property_len (ZMTP_PROPERTY_IDENTITY, options.routing_id_size)
                : 0);
}

void zmq::mechanism_t::make_command_with_basic_properties (
  msg_t *msg_, const char *prefix_, size_t prefix_len_) const
{
    const size_t command_size = prefix_len_ + basic_properties_len ();
    const int rc = msg_->init_size (command_size);
    errno_assert (rc == 0);

    unsigned char *ptr = static_cast<unsigned char *> (msg_->data ());

    //  Add prefix
    memcpy (ptr, prefix_, prefix_len_);
    ptr += prefix_len_;

    add_basic_properties (
      ptr, command_size - (ptr - static_cast<unsigned char *> (msg_->data ())));
}

int zmq::mechanism_t::parse_metadata (const unsigned char *ptr_,
                                      size_t length_,
                                      bool zap_flag_)
{
    size_t bytes_left = length_;

    while (bytes_left > 1) {
        const size_t name_length = static_cast<size_t> (*ptr_);
        ptr_ += name_len_size;
        bytes_left -= name_len_size;
        if (bytes_left < name_length)
            break;

        const std::string name =
          std::string (reinterpret_cast<const char *> (ptr_), name_length);
        ptr_ += name_length;
        bytes_left -= name_length;
        if (bytes_left < value_len_size)
            break;

        const size_t value_length = static_cast<size_t> (get_uint32 (ptr_));
        ptr_ += value_len_size;
        bytes_left -= value_len_size;
        if (bytes_left < value_length)
            break;

        const uint8_t *value = ptr_;
        ptr_ += value_length;
        bytes_left -= value_length;

        if (name == ZMTP_PROPERTY_IDENTITY && options.recv_routing_id)
            set_peer_routing_id (value, value_length);
        else if (name == ZMTP_PROPERTY_SOCKET_TYPE) {
            if (!check_socket_type (reinterpret_cast<const char *> (value),
                                    value_length)) {
                errno = EINVAL;
                return -1;
            }
        } else {
            const int rc = property (name, value, value_length);
            if (rc == -1)
                return -1;
        }
        (zap_flag_ ? _zap_properties : _zmtp_properties)
          .ZMQ_MAP_INSERT_OR_EMPLACE (
            name,
            std::string (reinterpret_cast<const char *> (value), value_length));
    }
    if (bytes_left > 0) {
        errno = EPROTO;
        return -1;
    }
    return 0;
}

int zmq::mechanism_t::property (const std::string & /* name_ */,
                                const void * /* value_ */,
                                size_t /* length_ */)
{
    //  Default implementation does not check
    //  property values and returns 0 to signal success.
    return 0;
}

template <size_t N>
static bool strequals (const char *actual_type_,
                       const size_t actual_len_,
                       const char (&expected_type_)[N])
{
    return actual_len_ == N - 1
           && memcmp (actual_type_, expected_type_, N - 1) == 0;
}

bool zmq::mechanism_t::check_socket_type (const char *type_,
                                          const size_t len_) const
{
    switch (options.type) {
        case ZMQ_REQ:
            return strequals (type_, len_, socket_type_rep)
                   || strequals (type_, len_, socket_type_router);
        case ZMQ_REP:
            return strequals (type_, len_, socket_type_req)
                   || strequals (type_, len_, socket_type_dealer);
        case ZMQ_DEALER:
            return strequals (type_, len_, socket_type_rep)
                   || strequals (type_, len_, socket_type_dealer)
                   || strequals (type_, len_, socket_type_router);
        case ZMQ_ROUTER:
            return strequals (type_, len_, socket_type_req)
                   || strequals (type_, len_, socket_type_dealer)
                   || strequals (type_, len_, socket_type_router);
        case ZMQ_PUSH:
            return strequals (type_, len_, socket_type_pull);
        case ZMQ_PULL:
            return strequals (type_, len_, socket_type_push);
        case ZMQ_PUB:
            return strequals (type_, len_, socket_type_sub)
                   || strequals (type_, len_, socket_type_xsub);
        case ZMQ_SUB:
            return strequals (type_, len_, socket_type_pub)
                   || strequals (type_, len_, socket_type_xpub);
        case ZMQ_XPUB:
            return strequals (type_, len_, socket_type_sub)
                   || strequals (type_, len_, socket_type_xsub);
        case ZMQ_XSUB:
            return strequals (type_, len_, socket_type_pub)
                   || strequals (type_, len_, socket_type_xpub);
        case ZMQ_PAIR:
            return strequals (type_, len_, socket_type_pair);
#ifdef ZMQ_BUILD_DRAFT_API
        case ZMQ_SERVER:
            return strequals (type_, len_, socket_type_client);
        case ZMQ_CLIENT:
            return strequals (type_, len_, socket_type_server);
        case ZMQ_RADIO:
            return strequals (type_, len_, socket_type_dish);
        case ZMQ_DISH:
            return strequals (type_, len_, socket_type_radio);
        case ZMQ_GATHER:
            return strequals (type_, len_, socket_type_scatter);
        case ZMQ_SCATTER:
            return strequals (type_, len_, socket_type_gather);
        case ZMQ_DGRAM:
            return strequals (type_, len_, socket_type_dgram);
        case ZMQ_PEER:
            return strequals (type_, len_, socket_type_peer);
        case ZMQ_CHANNEL:
            return strequals (type_, len_, socket_type_channel);
#endif
        default:
            break;
    }
    return false;
}
