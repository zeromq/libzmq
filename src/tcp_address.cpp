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
#include "tcp_address.hpp"
#include "stdint.hpp"
#include "err.hpp"
#include "ip.hpp"

#ifndef ZMQ_HAVE_WINDOWS
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <netdb.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#endif

zmq::tcp_address_t::tcp_address_t () : _has_src_addr (false)
{
    memset (&address, 0, sizeof (address));
    memset (&source_address, 0, sizeof (source_address));
}

zmq::tcp_address_t::tcp_address_t (const sockaddr *sa, socklen_t sa_len) :
    _has_src_addr (false)
{
    zmq_assert (sa && sa_len > 0);

    memset (&address, 0, sizeof (address));
    memset (&source_address, 0, sizeof (source_address));
    if (sa->sa_family == AF_INET
        && sa_len >= static_cast<socklen_t> (sizeof (address.ipv4)))
        memcpy (&address.ipv4, sa, sizeof (address.ipv4));
    else if (sa->sa_family == AF_INET6
             && sa_len >= static_cast<socklen_t> (sizeof (address.ipv6)))
        memcpy (&address.ipv6, sa, sizeof (address.ipv6));
}

zmq::tcp_address_t::~tcp_address_t ()
{
}

int zmq::tcp_address_t::resolve (const char *name_, bool local_, bool ipv6_)
{
    // Test the ';' to know if we have a source address in name_
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
          .ipv6 (ipv6_)
          .expect_port (true);

        ip_resolver_t src_resolver (src_resolver_opts);

        const int rc =
          src_resolver.resolve (&source_address, src_name.c_str ());
        if (rc != 0)
            return -1;
        name_ = src_delimiter + 1;
        _has_src_addr = true;
    }

    ip_resolver_options_t resolver_opts;

    resolver_opts.bindable (local_)
      .allow_dns (!local_)
      .allow_nic_name (local_)
      .ipv6 (ipv6_)
      .expect_port (true);

    ip_resolver_t resolver (resolver_opts);

    return resolver.resolve (&address, name_);
}

int zmq::tcp_address_t::to_string (std::string &addr_)
{
    if (address.family () != AF_INET && address.family () != AF_INET6) {
        addr_.clear ();
        return -1;
    }

    //  Not using service resolving because of
    //  https://github.com/zeromq/libzmq/commit/1824574f9b5a8ce786853320e3ea09fe1f822bc4
    char hbuf[NI_MAXHOST];
    int rc = getnameinfo (addr (), addrlen (), hbuf, sizeof (hbuf), NULL, 0,
                          NI_NUMERICHOST);
    if (rc != 0) {
        addr_.clear ();
        return rc;
    }

    if (address.family () == AF_INET6) {
        std::stringstream s;
        s << "tcp://[" << hbuf << "]:" << ntohs (address.ipv6.sin6_port);
        addr_ = s.str ();
    } else {
        std::stringstream s;
        s << "tcp://" << hbuf << ":" << ntohs (address.ipv4.sin_port);
        addr_ = s.str ();
    }
    return 0;
}

const sockaddr *zmq::tcp_address_t::addr () const
{
    return &address.generic;
}

socklen_t zmq::tcp_address_t::addrlen () const
{
    if (address.generic.sa_family == AF_INET6)
        return static_cast<socklen_t> (sizeof (address.ipv6));
    else
        return static_cast<socklen_t> (sizeof (address.ipv4));
}

const sockaddr *zmq::tcp_address_t::src_addr () const
{
    return &source_address.generic;
}

socklen_t zmq::tcp_address_t::src_addrlen () const
{
    if (address.family () == AF_INET6)
        return static_cast<socklen_t> (sizeof (source_address.ipv6));
    else
        return static_cast<socklen_t> (sizeof (source_address.ipv4));
}

bool zmq::tcp_address_t::has_src_addr () const
{
    return _has_src_addr;
}

#if defined ZMQ_HAVE_WINDOWS
unsigned short zmq::tcp_address_t::family () const
#else
sa_family_t zmq::tcp_address_t::family () const
#endif
{
    return address.family ();
}

zmq::tcp_address_mask_t::tcp_address_mask_t () :
    tcp_address_t (),
    address_mask (-1)
{
}

int zmq::tcp_address_mask_t::mask () const
{
    return address_mask;
}

int zmq::tcp_address_mask_t::resolve (const char *name_, bool ipv6_)
{
    // Find '/' at the end that separates address from the cidr mask number.
    // Allow empty mask clause and treat it like '/32' for ipv4 or '/128' for ipv6.
    std::string addr_str, mask_str;
    const char *delimiter = strrchr (name_, '/');
    if (delimiter != NULL) {
        addr_str.assign (name_, delimiter - name_);
        mask_str.assign (delimiter + 1);
        if (mask_str.empty ()) {
            errno = EINVAL;
            return -1;
        }
    } else
        addr_str.assign (name_);

    // Parse address part using standard routines.
    ip_resolver_options_t resolver_opts;

    resolver_opts.bindable (false)
      .allow_dns (false)
      .allow_nic_name (false)
      .ipv6 (ipv6_)
      .expect_port (false);

    ip_resolver_t resolver (resolver_opts);

    const int rc = resolver.resolve (&address, addr_str.c_str ());
    if (rc != 0)
        return rc;

    // Parse the cidr mask number.
    if (mask_str.empty ()) {
        if (address.family () == AF_INET6)
            address_mask = 128;
        else
            address_mask = 32;
    } else if (mask_str == "0")
        address_mask = 0;
    else {
        const int mask = atoi (mask_str.c_str ());
        if ((mask < 1) || (address.family () == AF_INET6 && mask > 128)
            || (address.family () != AF_INET6 && mask > 32)) {
            errno = EINVAL;
            return -1;
        }
        address_mask = mask;
    }

    return 0;
}

int zmq::tcp_address_mask_t::to_string (std::string &addr_)
{
    if (address.family () != AF_INET && address.family () != AF_INET6) {
        addr_.clear ();
        return -1;
    }
    if (address_mask == -1) {
        addr_.clear ();
        return -1;
    }

    char hbuf[NI_MAXHOST];
    int rc = getnameinfo (addr (), addrlen (), hbuf, sizeof (hbuf), NULL, 0,
                          NI_NUMERICHOST);
    if (rc != 0) {
        addr_.clear ();
        return rc;
    }

    if (address.family () == AF_INET6) {
        std::stringstream s;
        s << "[" << hbuf << "]/" << address_mask;
        addr_ = s.str ();
    } else {
        std::stringstream s;
        s << hbuf << "/" << address_mask;
        addr_ = s.str ();
    }
    return 0;
}

bool zmq::tcp_address_mask_t::match_address (const struct sockaddr *ss,
                                             const socklen_t ss_len) const
{
    zmq_assert (address_mask != -1 && ss != NULL
                && ss_len >= (socklen_t) sizeof (struct sockaddr));

    if (ss->sa_family != address.generic.sa_family)
        return false;

    if (address_mask > 0) {
        int mask;
        const uint8_t *our_bytes, *their_bytes;
        if (ss->sa_family == AF_INET6) {
            zmq_assert (ss_len == sizeof (struct sockaddr_in6));
            their_bytes = reinterpret_cast<const uint8_t *> (&(
              (reinterpret_cast<const struct sockaddr_in6 *> (ss))->sin6_addr));
            our_bytes =
              reinterpret_cast<const uint8_t *> (&address.ipv6.sin6_addr);
            mask = sizeof (struct in6_addr) * 8;
        } else {
            zmq_assert (ss_len == sizeof (struct sockaddr_in));
            their_bytes = reinterpret_cast<const uint8_t *> (
              &((reinterpret_cast<const struct sockaddr_in *> (ss))->sin_addr));
            our_bytes =
              reinterpret_cast<const uint8_t *> (&address.ipv4.sin_addr);
            mask = sizeof (struct in_addr) * 8;
        }
        if (address_mask < mask)
            mask = address_mask;

        const size_t full_bytes = mask / 8;
        if (memcmp (our_bytes, their_bytes, full_bytes))
            return false;

        const uint8_t last_byte_bits = 0xffU << (8 - mask % 8);
        if (last_byte_bits) {
            if ((their_bytes[full_bytes] & last_byte_bits)
                != (our_bytes[full_bytes] & last_byte_bits))
                return false;
        }
    }

    return true;
}
