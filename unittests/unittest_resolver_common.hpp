/*
Copyright (c) 2018 Contributors as noted in the AUTHORS file

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

#ifndef __UNITTEST_RESOLVER_COMMON_INCLUDED__
#define __UNITTEST_RESOLVER_COMMON_INCLUDED__

#include <ip_resolver.hpp>
#include <string.h>

//  Attempt a resolution and test the results.
//
//  On windows we can receive an IPv4 address even when an IPv6 is requested, if
//  we're in this situation then we compare to 'expected_addr_v4_failover_'
//  instead.
void validate_address (int family,
                       const zmq::ip_addr_t *addr_,
                       const char *expected_addr_,
                       uint16_t expected_port_ = 0,
                       uint16_t expected_zone_ = 0,
                       const char *expected_addr_v4_failover_ = NULL)
{
#if defined ZMQ_HAVE_WINDOWS
    if (family == AF_INET6 && expected_addr_v4_failover_ != NULL
        && addr_->family () == AF_INET) {
        //  We've requested an IPv6 but the system gave us an IPv4, use the
        //  failover address
        family = AF_INET;
        expected_addr_ = expected_addr_v4_failover_;
    }
#else
    (void) expected_addr_v4_failover_;
#endif

    TEST_ASSERT_EQUAL (family, addr_->family ());

    if (family == AF_INET6) {
        struct in6_addr expected_addr;
        const sockaddr_in6 *ip6_addr = &addr_->ipv6;

        TEST_ASSERT_EQUAL (
          1, test_inet_pton (AF_INET6, expected_addr_, &expected_addr));

        int neq = memcmp (&ip6_addr->sin6_addr, &expected_addr,
                          sizeof (expected_addr_));

        TEST_ASSERT_EQUAL (0, neq);
        TEST_ASSERT_EQUAL (htons (expected_port_), ip6_addr->sin6_port);
        TEST_ASSERT_EQUAL (expected_zone_, ip6_addr->sin6_scope_id);
    } else {
        struct in_addr expected_addr;
        const sockaddr_in *ip4_addr = &addr_->ipv4;

        TEST_ASSERT_EQUAL (
          1, test_inet_pton (AF_INET, expected_addr_, &expected_addr));

        TEST_ASSERT_EQUAL (expected_addr.s_addr, ip4_addr->sin_addr.s_addr);
        TEST_ASSERT_EQUAL (htons (expected_port_), ip4_addr->sin_port);
    }
}

#endif // __UNITTEST_RESOLVER_COMMON_INCLUDED__
