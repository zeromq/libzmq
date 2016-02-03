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

#ifndef __ZMQ_ADDRESS_HPP_INCLUDED__
#define __ZMQ_ADDRESS_HPP_INCLUDED__

#include <string>

namespace zmq
{
    class ctx_t;
    class tcp_address_t;
    class udp_address_t;
#if !defined ZMQ_HAVE_WINDOWS && !defined ZMQ_HAVE_OPENVMS
    class ipc_address_t;
#endif
#if defined ZMQ_HAVE_LINUX
    class tipc_address_t;
#endif
#if defined ZMQ_HAVE_VMCI
    class vmci_address_t;
#endif
    struct address_t {
        address_t (const std::string &protocol_, const std::string &address_, ctx_t *parent_);

        ~address_t ();

        const std::string protocol;
        const std::string address;
        ctx_t *parent;

        //  Protocol specific resolved address
        union {
            tcp_address_t *tcp_addr;
            udp_address_t *udp_addr;
#if !defined ZMQ_HAVE_WINDOWS && !defined ZMQ_HAVE_OPENVMS
            ipc_address_t *ipc_addr;
#endif
#if defined ZMQ_HAVE_LINUX
            tipc_address_t *tipc_addr;
#endif
#if defined ZMQ_HAVE_VMCI
            vmci_address_t *vmci_addr;
#endif
        } resolved;

        int to_string (std::string &addr_) const;
    };
}

#endif
