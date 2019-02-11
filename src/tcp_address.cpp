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

#include <limits.h>

zmq::tcp_address_t::tcp_address_t () : _has_src_addr (false)
{
    memset (&_address, 0, sizeof (_address));
    memset (&_source_address, 0, sizeof (_source_address));
}

zmq::tcp_address_t::tcp_address_t (const sockaddr *sa_, socklen_t sa_len_) :
    _has_src_addr (false)
{
    zmq_assert (sa_ && sa_len_ > 0);

    memset (&_address, 0, sizeof (_address));
    memset (&_source_address, 0, sizeof (_source_address));
    if (sa_->sa_family == AF_INET
        && sa_len_ >= static_cast<socklen_t> (sizeof (_address.ipv4)))
        memcpy (&_address.ipv4, sa_, sizeof (_address.ipv4));
    else if (sa_->sa_family == AF_INET6
             && sa_len_ >= static_cast<socklen_t> (sizeof (_address.ipv6)))
        memcpy (&_address.ipv6, sa_, sizeof (_address.ipv6));
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
          src_resolver.resolve (&_source_address, src_name.c_str ());
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

    return resolver.resolve (&_address, name_);
}

template <size_t N1, size_t N2>
static std::string make_address_string (const char *hbuf,
                                        uint16_t port,
                                        const char (&ipv6_prefix)[N1],
                                        const char (&ipv6_suffix)[N2])
{
    const size_t max_port_str_length = 5;
    char buf[NI_MAXHOST + sizeof ipv6_prefix + sizeof ipv6_suffix
             + max_port_str_length];
    char *pos = buf;
    memcpy (pos, ipv6_prefix, sizeof ipv6_prefix - 1);
    pos += sizeof ipv6_prefix - 1;
    const size_t hbuf_len = strlen (hbuf);
    memcpy (pos, hbuf, hbuf_len);
    pos += hbuf_len;
    memcpy (pos, ipv6_suffix, sizeof ipv6_suffix - 1);
    pos += sizeof ipv6_suffix - 1;
    pos += sprintf (pos, "%d", ntohs (port));
    return std::string (buf, pos - buf);
}

int zmq::tcp_address_t::to_string (std::string &addr_) const
{
    if (_address.family () != AF_INET && _address.family () != AF_INET6) {
        addr_.clear ();
        return -1;
    }

    //  Not using service resolving because of
    //  https://github.com/zeromq/libzmq/commit/1824574f9b5a8ce786853320e3ea09fe1f822bc4
    char hbuf[NI_MAXHOST];
    const int rc = getnameinfo (addr (), addrlen (), hbuf, sizeof (hbuf), NULL,
                                0, NI_NUMERICHOST);
    if (rc != 0) {
        addr_.clear ();
        return rc;
    }

    const char ipv4_prefix[] = "tcp://";
    const char ipv4_suffix[] = ":";
    const char ipv6_prefix[] = "tcp://[";
    const char ipv6_suffix[] = "]:";
    if (_address.family () == AF_INET6) {
        addr_ = make_address_string (hbuf, _address.ipv6.sin6_port, ipv6_prefix,
                                     ipv6_suffix);
    } else {
        addr_ = make_address_string (hbuf, _address.ipv4.sin_port, ipv4_prefix,
                                     ipv4_suffix);
    }
    return 0;
}

const sockaddr *zmq::tcp_address_t::addr () const
{
    return _address.as_sockaddr ();
}

socklen_t zmq::tcp_address_t::addrlen () const
{
    return _address.sockaddr_len ();
}

const sockaddr *zmq::tcp_address_t::src_addr () const
{
    return _source_address.as_sockaddr ();
}

socklen_t zmq::tcp_address_t::src_addrlen () const
{
    return _source_address.sockaddr_len ();
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
    return _address.family ();
}

zmq::tcp_address_mask_t::tcp_address_mask_t () : _address_mask (-1)
{
    memset (&_network_address, 0, sizeof (_network_address));
}

int zmq::tcp_address_mask_t::mask () const
{
    return _address_mask;
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

    const int rc = resolver.resolve (&_network_address, addr_str.c_str ());
    if (rc != 0)
        return rc;

    // Parse the cidr mask number.
    const int full_mask_ipv4 =
      sizeof (_network_address.ipv4.sin_addr) * CHAR_BIT;
    const int full_mask_ipv6 =
      sizeof (_network_address.ipv6.sin6_addr) * CHAR_BIT;
    if (mask_str.empty ()) {
        _address_mask = _network_address.family () == AF_INET6 ? full_mask_ipv6
                                                               : full_mask_ipv4;
    } else if (mask_str == "0")
        _address_mask = 0;
    else {
        const long mask = strtol (mask_str.c_str (), NULL, 10);
        if ((mask < 1)
            || (_network_address.family () == AF_INET6 && mask > full_mask_ipv6)
            || (_network_address.family () != AF_INET6
                && mask > full_mask_ipv4)) {
            errno = EINVAL;
            return -1;
        }
        _address_mask = static_cast<int> (mask);
    }

    return 0;
}

int zmq::tcp_address_mask_t::to_string (std::string &addr_) const
{
    if (_network_address.family () != AF_INET
        && _network_address.family () != AF_INET6) {
        addr_.clear ();
        return -1;
    }
    if (_address_mask == -1) {
        addr_.clear ();
        return -1;
    }

    char hbuf[NI_MAXHOST];
    const int rc = getnameinfo (_network_address.as_sockaddr (),
                                _network_address.sockaddr_len (), hbuf,
                                sizeof (hbuf), NULL, 0, NI_NUMERICHOST);
    if (rc != 0) {
        addr_.clear ();
        return rc;
    }

    const size_t max_mask_len = 4;
    const char ipv6_prefix[] = "[";
    const char ipv6_suffix[] = "]/";
    const char ipv4_suffix[] = "/";
    char
      buf[NI_MAXHOST + sizeof ipv6_prefix + sizeof ipv6_suffix + max_mask_len];
    char *pos = buf;
    if (_network_address.family () == AF_INET6) {
        memcpy (pos, ipv6_prefix, sizeof ipv6_prefix - 1);
        pos += sizeof ipv6_prefix - 1;
    }
    const size_t hbuf_len = strlen (hbuf);
    memcpy (pos, hbuf, hbuf_len);
    pos += hbuf_len;
    if (_network_address.family () == AF_INET6) {
        memcpy (pos, ipv6_suffix, sizeof ipv6_suffix - 1);
        pos += sizeof ipv6_suffix - 1;
    } else {
        memcpy (pos, ipv4_suffix, sizeof ipv4_suffix - 1);
        pos += sizeof ipv4_suffix - 1;
    }
    pos += sprintf (pos, "%d", _address_mask);
    addr_.assign (buf, pos - buf);
    return 0;
}

bool zmq::tcp_address_mask_t::match_address (const struct sockaddr *ss_,
                                             const socklen_t ss_len_) const
{
    zmq_assert (_address_mask != -1 && ss_ != NULL
                && ss_len_
                     >= static_cast<socklen_t> (sizeof (struct sockaddr)));

    if (ss_->sa_family != _network_address.generic.sa_family)
        return false;

    if (_address_mask > 0) {
        int mask;
        const uint8_t *our_bytes, *their_bytes;
        if (ss_->sa_family == AF_INET6) {
            zmq_assert (ss_len_ == sizeof (struct sockaddr_in6));
            their_bytes = reinterpret_cast<const uint8_t *> (
              &((reinterpret_cast<const struct sockaddr_in6 *> (ss_))
                  ->sin6_addr));
            our_bytes = reinterpret_cast<const uint8_t *> (
              &_network_address.ipv6.sin6_addr);
            mask = sizeof (struct in6_addr) * 8;
        } else {
            zmq_assert (ss_len_ == sizeof (struct sockaddr_in));
            their_bytes = reinterpret_cast<const uint8_t *> (&(
              (reinterpret_cast<const struct sockaddr_in *> (ss_))->sin_addr));
            our_bytes = reinterpret_cast<const uint8_t *> (
              &_network_address.ipv4.sin_addr);
            mask = sizeof (struct in_addr) * 8;
        }
        if (_address_mask < mask)
            mask = _address_mask;

        const size_t full_bytes = mask / 8;
        if (memcmp (our_bytes, their_bytes, full_bytes) != 0)
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
