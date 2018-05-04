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
#include <string>
#include <sstream>

#include "macros.hpp"
#include "udp_address.hpp"
#include "stdint.hpp"
#include "err.hpp"
#include "ip.hpp"

#ifndef ZMQ_HAVE_WINDOWS
#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ctype.h>
#endif

#include "ip_resolver.hpp"

zmq::udp_address_t::udp_address_t () : is_multicast (false)
{
    memset (&bind_address, 0, sizeof bind_address);
    memset (&dest_address, 0, sizeof dest_address);
}

zmq::udp_address_t::~udp_address_t ()
{
}

int zmq::udp_address_t::resolve (const char *name_, bool bind_)
{
    //  No IPv6 support yet
    int family = AF_INET;
    bool ipv6 = family == AF_INET6;
    bool has_interface = false;
    ip_addr_t interface_addr;

    //  If we have a semicolon then we should have an interface specifier in the
    //  URL
    const char *src_delimiter = strrchr (name_, ';');
    if (src_delimiter) {
        std::string src_name (name_, src_delimiter - name_);

        ip_resolver_options_t src_resolver_opts;

        src_resolver_opts
          .bindable (true)
          //  Restrict hostname/service to literals to avoid any DNS
          //  lookups or service-name irregularity due to
          //  indeterminate socktype.
          .allow_dns (false)
          .allow_nic_name (true)
          .ipv6 (ipv6)
          .expect_port (false);

        ip_resolver_t src_resolver (src_resolver_opts);

        const int rc =
          src_resolver.resolve (&interface_addr, src_name.c_str ());

        if (rc != 0) {
            return -1;
        }

        if (interface_addr.is_multicast ()) {
            //  It doesn't make sense to have a multicast address as a source
            errno = EINVAL;
            return -1;
        }

        has_interface = true;
        name_ = src_delimiter + 1;
    }

    ip_resolver_options_t resolver_opts;

    resolver_opts.bindable (bind_)
      .allow_dns (!bind_)
      .allow_nic_name (bind_)
      .expect_port (true)
      .ipv6 (ipv6);

    ip_resolver_t resolver (resolver_opts);

    ip_addr_t target_addr;

    int rc = resolver.resolve (&target_addr, name_);
    if (rc != 0) {
        return -1;
    }

    is_multicast = target_addr.is_multicast ();
    uint16_t port = target_addr.port ();

    if (has_interface) {
        //  If we have an interface specifier then the target address must be a
        //  multicast address
        if (!is_multicast) {
            errno = EINVAL;
            return -1;
        }

        interface_addr.set_port (port);

        dest_address = target_addr.ipv4;
        bind_address = interface_addr.ipv4;
    } else {
        //  If we don't have an explicit interface specifier then the URL is
        //  ambiguous: if the target address is multicast then it's the
        //  destination address and the bind address is ANY, if it's unicast
        //  then it's the bind address when 'bind_' is true and the destination
        //  otherwise
        ip_addr_t any = ip_addr_t::any (family);
        any.set_port (port);

        if (is_multicast) {
            dest_address = target_addr.ipv4;
            bind_address = any.ipv4;
        } else {
            if (bind_) {
                dest_address = target_addr.ipv4;
                bind_address = target_addr.ipv4;
            } else {
                dest_address = target_addr.ipv4;
                bind_address = any.ipv4;
            }
        }
    }

    if (is_multicast) {
        multicast = dest_address.sin_addr;
    }

    address = name_;

    return 0;
}

int zmq::udp_address_t::to_string (std::string &addr_)
{
    addr_ = address;
    return 0;
}

bool zmq::udp_address_t::is_mcast () const
{
    return is_multicast;
}

const sockaddr *zmq::udp_address_t::bind_addr () const
{
    return (sockaddr *) &bind_address;
}

socklen_t zmq::udp_address_t::bind_addrlen () const
{
    return sizeof (sockaddr_in);
}

const sockaddr *zmq::udp_address_t::dest_addr () const
{
    return (sockaddr *) &dest_address;
}

socklen_t zmq::udp_address_t::dest_addrlen () const
{
    return sizeof (sockaddr_in);
}

const in_addr zmq::udp_address_t::multicast_ip () const
{
    return multicast;
}

const in_addr zmq::udp_address_t::interface_ip () const
{
    return iface;
}

#if defined ZMQ_HAVE_WINDOWS
unsigned short zmq::udp_address_t::family () const
#else
sa_family_t zmq::udp_address_t::family () const
#endif
{
    return AF_INET;
}
