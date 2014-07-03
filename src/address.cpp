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
#include "address.hpp"
#include "err.hpp"
#include "tcp_address.hpp"
#include "ipc_address.hpp"
#include "tipc_address.hpp"

#include <string>
#include <sstream>

zmq::address_t::address_t (
    const std::string &protocol_, const std::string &address_)
    : protocol (protocol_),
      address (address_)
{
    memset (&resolved, 0, sizeof resolved);
}

zmq::address_t::~address_t ()
{
    if (protocol == "tcp") {
        if (resolved.tcp_addr) {
            delete resolved.tcp_addr;
            resolved.tcp_addr = 0;
        }
    }
#if !defined ZMQ_HAVE_WINDOWS && !defined ZMQ_HAVE_OPENVMS
    else
    if (protocol == "ipc") {
        if (resolved.ipc_addr) {
            delete resolved.ipc_addr;
            resolved.ipc_addr = 0;
        }
    }
#endif
#if defined ZMQ_HAVE_TIPC
    else
    if (protocol == "tipc") {
        if (resolved.tipc_addr) {
            delete resolved.tipc_addr;
            resolved.tipc_addr = 0;
        }
    }
#endif
}

int zmq::address_t::to_string (std::string &addr_) const
{
    if (protocol == "tcp") {
        if (resolved.tcp_addr)
            return resolved.tcp_addr->to_string (addr_);
    }
#if !defined ZMQ_HAVE_WINDOWS && !defined ZMQ_HAVE_OPENVMS
    else
    if (protocol == "ipc") {
        if (resolved.ipc_addr)
            return resolved.ipc_addr->to_string (addr_);
    }
#endif
#if defined ZMQ_HAVE_TIPC
    else
    if (protocol == "tipc") {
        if (resolved.tipc_addr)
            return resolved.tipc_addr->to_string (addr_);
    }
#endif

    if (!protocol.empty () && !address.empty ()) {
        std::stringstream s;
        s << protocol << "://" << address;
        addr_ = s.str ();
        return 0;
    }
    addr_.clear ();
    return -1;
}
