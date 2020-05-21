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
#include <net/if.h>
#include <ctype.h>
#endif

zmq::udp_address_t::udp_address_t () :
    _bind_interface (-1),
    _is_multicast (false)
{
    _bind_address = ip_addr_t::any (AF_INET);
    _target_address = ip_addr_t::any (AF_INET);
}

zmq::udp_address_t::~udp_address_t ()
{
}

int zmq::udp_address_t::resolve (const char *name_, bool bind_, bool ipv6_)
{
    //  No IPv6 support yet
    bool has_interface = false;

    _address = name_;

    //  If we have a semicolon then we should have an interface specifier in the
    //  URL
    const char *src_delimiter = strrchr (name_, ';');
    if (src_delimiter) {
        const std::string src_name (name_, src_delimiter - name_);

        ip_resolver_options_t src_resolver_opts;

        src_resolver_opts
          .bindable (true)
          //  Restrict hostname/service to literals to avoid any DNS
          //  lookups or service-name irregularity due to
          //  indeterminate socktype.
          .allow_dns (false)
          .allow_nic_name (true)
          .ipv6 (ipv6_)
          .expect_port (false);

        ip_resolver_t src_resolver (src_resolver_opts);

        const int rc = src_resolver.resolve (&_bind_address, src_name.c_str ());

        if (rc != 0) {
            return -1;
        }

        if (_bind_address.is_multicast ()) {
            //  It doesn't make sense to have a multicast address as a source
            errno = EINVAL;
            return -1;
        }

        //  This is a hack because we need the interface index when binding
        //  multicast IPv6, we can't do it by address. Unfortunately for the
        //  time being we don't have a generic platform-independent function to
        //  resolve an interface index from an address, so we only support it
        //  when an actual interface name is provided.
        if (src_name == "*") {
            _bind_interface = 0;
        } else {
#if _WIN32_WINNT > _WIN32_WINNT_WINXP && !defined ZMQ_HAVE_WINDOWS_UWP         \
  && !defined ZMQ_HAVE_VXWORKS
            _bind_interface = if_nametoindex (src_name.c_str ());
            if (_bind_interface == 0) {
                //  Error, probably not an interface name.
                _bind_interface = -1;
            }
#endif
        }

        has_interface = true;
        name_ = src_delimiter + 1;
    }

    ip_resolver_options_t resolver_opts;

    resolver_opts.bindable (bind_)
      .allow_dns (!bind_)
      .allow_nic_name (bind_)
      .expect_port (true)
      .ipv6 (ipv6_);

    ip_resolver_t resolver (resolver_opts);

    const int rc = resolver.resolve (&_target_address, name_);
    if (rc != 0) {
        return -1;
    }

    _is_multicast = _target_address.is_multicast ();
    const uint16_t port = _target_address.port ();

    if (has_interface) {
        //  If we have an interface specifier then the target address must be a
        //  multicast address
        if (!_is_multicast) {
            errno = EINVAL;
            return -1;
        }

        _bind_address.set_port (port);
    } else {
        //  If we don't have an explicit interface specifier then the URL is
        //  ambiguous: if the target address is multicast then it's the
        //  destination address and the bind address is ANY, if it's unicast
        //  then it's the bind address when 'bind_' is true and the destination
        //  otherwise
        if (_is_multicast || !bind_) {
            _bind_address = ip_addr_t::any (_target_address.family ());
            _bind_address.set_port (port);
            _bind_interface = 0;
        } else {
            //  If we were asked for a bind socket and the address
            //  provided was not multicast then it was really meant as
            //  a bind address and the target_address is useless.
            _bind_address = _target_address;
        }
    }

    if (_bind_address.family () != _target_address.family ()) {
        errno = EINVAL;
        return -1;
    }

    //  For IPv6 multicast we *must* have an interface index since we can't
    //  bind by address.
    if (ipv6_ && _is_multicast && _bind_interface < 0) {
        errno = ENODEV;
        return -1;
    }

    return 0;
}

int zmq::udp_address_t::family () const
{
    return _bind_address.family ();
}

bool zmq::udp_address_t::is_mcast () const
{
    return _is_multicast;
}

const zmq::ip_addr_t *zmq::udp_address_t::bind_addr () const
{
    return &_bind_address;
}

int zmq::udp_address_t::bind_if () const
{
    return _bind_interface;
}

const zmq::ip_addr_t *zmq::udp_address_t::target_addr () const
{
    return &_target_address;
}

int zmq::udp_address_t::to_string (std::string &addr_)
{
    // XXX what do (factor TCP code?)
    addr_ = _address;
    return 0;
}
