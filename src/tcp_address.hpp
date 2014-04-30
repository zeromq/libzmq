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
        tcp_address_t (const sockaddr *sa, socklen_t sa_len);
        virtual ~tcp_address_t ();

        //  This function translates textual TCP address into an address
        //  strcuture. If 'local' is true, names are resolved as local interface
        //  names. If it is false, names are resolved as remote hostnames.
        //  If 'ipv6' is true, the name may resolve to IPv6 address.
        int resolve (const char *name_, bool local_, bool ipv6_, bool is_src_ = false);

        //  The opposite to resolve()
        virtual int to_string (std::string &addr_);

#if defined ZMQ_HAVE_WINDOWS
        unsigned short family () const;
#else
        sa_family_t family () const;
#endif
        const sockaddr *addr () const;
        socklen_t addrlen () const;

        const sockaddr *src_addr () const;
        socklen_t src_addrlen () const;
        bool has_src_addr () const;

    protected:
        int resolve_nic_name (const char *nic_, bool ipv6_, bool is_src_ = false);
        int resolve_interface (const char *interface_, bool ipv6_, bool is_src_ = false);
        int resolve_hostname (const char *hostname_, bool ipv6_, bool is_src_ = false);

        union {
            sockaddr generic;
            sockaddr_in ipv4;
            sockaddr_in6 ipv6;
        } address;

        union {
            sockaddr generic;
            sockaddr_in ipv4;
            sockaddr_in6 ipv6;
        } source_address;
        bool _has_src_addr;
    };

    class tcp_address_mask_t : public tcp_address_t
    {
    public:
        tcp_address_mask_t ();

        // This function enhances tcp_address_t::resolve() with ability to parse
        // additional cidr-like(/xx) mask value at the end of the name string.
        // Works only with remote hostnames.
        int resolve (const char *name_, bool ipv6_);

        // The opposite to resolve()
        int to_string (std::string &addr_);

        int mask () const;

        bool match_address (const struct sockaddr *ss, const socklen_t ss_len) const;

    private:
        int address_mask;
    };

}

#endif
