/*
    Copyright (c) 2009-2011 250bpm s.r.o.
    Copyright (c) 2007-2009 iMatix Corporation
    Copyright (c) 2007-2011 Other contributors as noted in the AUTHORS file

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

#ifndef __ZMQ_TCP_ADDRESS_HPP_INCLUDED__
#define __ZMQ_TCP_ADDRESS_HPP_INCLUDED__

#include "platform.hpp"

#if defined ZMQ_HAVE_WINDOWS
#include "windows.hpp"
#else
#include <sys/socket.h>
#include <netinet/in.h>
#endif

namespace zmq
{

    class tcp_address_t
    {
    public:

        tcp_address_t ();
        ~tcp_address_t ();

        //  This function translates textual TCP address into an address
        //  strcuture. If 'local' is true, names are resolved as local interface
        //  names. If it is false, names are resolved as remote hostnames.
        //  If 'ipv4only' is true, the name will never resolve to IPv6 address.
        int resolve (const char* name_, bool local_, bool ipv4only_);

#if defined ZMQ_HAVE_WINDOWS
        unsigned short family ();
#else
        sa_family_t family ();
#endif
        sockaddr *addr ();
        socklen_t addrlen ();

    private:

        int resolve_nic_name (const char *nic_, bool ipv4only_);
        int resolve_interface (const char *interface_, bool ipv4only_);
        int resolve_hostname (const char *hostname_, bool ipv4only_);

        union {
            sockaddr generic;
            sockaddr_in ipv4;
            sockaddr_in6 ipv6;
        } address;

        tcp_address_t (const tcp_address_t&);
        const tcp_address_t &operator = (const tcp_address_t&);
    };
    
}

#endif

