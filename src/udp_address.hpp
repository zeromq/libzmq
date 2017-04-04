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

#ifndef __ZMQ_UDP_ADDRESS_HPP_INCLUDED__
#define __ZMQ_UDP_ADDRESS_HPP_INCLUDED__

#if !defined ZMQ_HAVE_WINDOWS
#include <sys/socket.h>
#include <netinet/in.h>
#endif

namespace zmq
{
    class udp_address_t
    {
    public:

        udp_address_t ();
        virtual ~udp_address_t ();

        int resolve (const char *name_, bool receiver_);

        //  The opposite to resolve()
        virtual int to_string (std::string &addr_);

#if defined ZMQ_HAVE_WINDOWS
        unsigned short family () const;
#else
        sa_family_t family () const;
#endif
        const sockaddr *bind_addr () const;
        socklen_t bind_addrlen () const;

        const sockaddr *dest_addr () const;
        socklen_t dest_addrlen () const;

        bool is_mcast () const;

        const in_addr multicast_ip () const;
        const in_addr interface_ip () const;

    private:
        in_addr  multicast;
        in_addr  iface;
        sockaddr_in bind_address;
        sockaddr_in dest_address;
        bool is_multicast;
        std::string address;
    };
}

#endif
