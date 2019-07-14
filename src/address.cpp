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
#include "address.hpp"
#include "ctx.hpp"
#include "err.hpp"
#include "tcp_address.hpp"
#include "udp_address.hpp"
#include "ipc_address.hpp"
#include "tipc_address.hpp"

#if defined ZMQ_HAVE_VMCI
#include "vmci_address.hpp"
#endif

#include <string>
#include <sstream>

zmq::address_t::address_t (const std::string &protocol_,
                           const std::string &address_,
                           ctx_t *parent_) :
    protocol (protocol_),
    address (address_),
    parent (parent_)
{
    resolved.dummy = NULL;
}

zmq::address_t::~address_t ()
{
    if (protocol == protocol_name::tcp || protocol == protocol_name::ws) {
        LIBZMQ_DELETE (resolved.tcp_addr);
    } else if (protocol == protocol_name::udp) {
        LIBZMQ_DELETE (resolved.udp_addr);
    }
#if !defined ZMQ_HAVE_WINDOWS && !defined ZMQ_HAVE_OPENVMS                     \
  && !defined ZMQ_HAVE_VXWORKS
    else if (protocol == protocol_name::ipc) {
        LIBZMQ_DELETE (resolved.ipc_addr);
    }
#endif
#if defined ZMQ_HAVE_TIPC
    else if (protocol == protocol_name::tipc) {
        LIBZMQ_DELETE (resolved.tipc_addr);
    }
#endif
#if defined ZMQ_HAVE_VMCI
    else if (protocol == protocol_name::vmci) {
        LIBZMQ_DELETE (resolved.vmci_addr);
    }
#endif
}

int zmq::address_t::to_string (std::string &addr_) const
{
    if (protocol == protocol_name::tcp && resolved.tcp_addr)
        return resolved.tcp_addr->to_string (addr_);
    if (protocol == protocol_name::udp && resolved.udp_addr)
        return resolved.udp_addr->to_string (addr_);
#if !defined ZMQ_HAVE_WINDOWS && !defined ZMQ_HAVE_OPENVMS                     \
  && !defined ZMQ_HAVE_VXWORKS
    if (protocol == protocol_name::ipc && resolved.ipc_addr)
        return resolved.ipc_addr->to_string (addr_);
#endif
#if defined ZMQ_HAVE_TIPC
    if (protocol == protocol_name::tipc && resolved.tipc_addr)
        return resolved.tipc_addr->to_string (addr_);
#endif
#if defined ZMQ_HAVE_VMCI
    if (protocol == protocol_name::vmci && resolved.vmci_addr)
        return resolved.vmci_addr->to_string (addr_);
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

zmq::zmq_socklen_t zmq::get_socket_address (fd_t fd_,
                                            socket_end_t socket_end_,
                                            sockaddr_storage *ss_)
{
    zmq_socklen_t sl = static_cast<zmq_socklen_t> (sizeof (*ss_));

    const int rc =
      socket_end_ == socket_end_local
        ? getsockname (fd_, reinterpret_cast<struct sockaddr *> (ss_), &sl)
        : getpeername (fd_, reinterpret_cast<struct sockaddr *> (ss_), &sl);

    return rc != 0 ? 0 : sl;
}
