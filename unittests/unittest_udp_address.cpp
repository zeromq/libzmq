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

#include <unity.h>
#include "../tests/testutil.hpp"
#include "../unittests/unittest_resolver_common.hpp"

#include <ip.hpp>
#include <udp_address.hpp>

void setUp ()
{
}

void tearDown ()
{
}

//  Test an UDP address resolution. If 'dest_addr_' is NULL assume the
//  resolution is supposed to fail.
static void test_resolve (bool bind_,
                          int family_,
                          const char *name_,
                          const char *target_addr_,
                          uint16_t expected_port_,
                          const char *bind_addr_,
                          bool multicast_)
{
    if (family_ == AF_INET6 && !is_ipv6_available ()) {
        TEST_IGNORE_MESSAGE ("ipv6 is not available");
    }

    zmq::udp_address_t addr;

    int rc = addr.resolve (name_, bind_, family_ == AF_INET6);

    if (target_addr_ == NULL) {
        TEST_ASSERT_EQUAL (-1, rc);
        TEST_ASSERT_EQUAL (EINVAL, errno);
        return;
    }
    TEST_ASSERT_EQUAL (0, rc);


    TEST_ASSERT_EQUAL (multicast_, addr.is_mcast ());

    if (bind_addr_ == NULL) {
        // Bind ANY
        if (family_ == AF_INET) {
            bind_addr_ = "0.0.0.0";
        } else {
            bind_addr_ = "::";
        }
    }

    validate_address (family_, addr.target_addr (), target_addr_,
                      expected_port_);
    validate_address (family_, addr.bind_addr (), bind_addr_, expected_port_);
}

static void test_resolve_bind (int family_,
                               const char *name_,
                               const char *dest_addr_,
                               uint16_t expected_port_ = 0,
                               const char *bind_addr_ = NULL,
                               bool multicast_ = false)
{
    test_resolve (true, family_, name_, dest_addr_, expected_port_, bind_addr_,
                  multicast_);
}

static void test_resolve_connect (int family_,
                                  const char *name_,
                                  const char *dest_addr_,
                                  uint16_t expected_port_ = 0,
                                  const char *bind_addr_ = NULL,
                                  bool multicast_ = false)
{
    test_resolve (false, family_, name_, dest_addr_, expected_port_, bind_addr_,
                  multicast_);
}

static void test_resolve_ipv4_simple ()
{
    test_resolve_connect (AF_INET, "127.0.0.1:5555", "127.0.0.1", 5555);
}

static void test_resolve_ipv6_simple ()
{
    test_resolve_connect (AF_INET6, "[::1]:123", "::1", 123);
}

static void test_resolve_ipv4_bind ()
{
    test_resolve_bind (AF_INET, "127.0.0.1:5555", "127.0.0.1", 5555,
                       "127.0.0.1");
}

static void test_resolve_ipv6_bind ()
{
    test_resolve_bind (AF_INET6, "[abcd::1234:1]:5555", "abcd::1234:1", 5555,
                       "abcd::1234:1");
}

static void test_resolve_ipv4_bind_any ()
{
    test_resolve_bind (AF_INET, "*:*", "0.0.0.0", 0, "0.0.0.0");
}

static void test_resolve_ipv6_bind_any ()
{
    test_resolve_bind (AF_INET6, "*:*", "::", 0, "::");
}

static void test_resolve_ipv4_bind_anyport ()
{
    test_resolve_bind (AF_INET, "127.0.0.1:*", "127.0.0.1", 0, "127.0.0.1");
}

static void test_resolve_ipv6_bind_anyport ()
{
    test_resolve_bind (AF_INET6, "[1:2:3:4::5]:*", "1:2:3:4::5", 0,
                       "1:2:3:4::5");
}

static void test_resolve_ipv4_bind_any_port ()
{
    test_resolve_bind (AF_INET, "*:5555", "0.0.0.0", 5555, "0.0.0.0");
}

static void test_resolve_ipv6_bind_any_port ()
{
    test_resolve_bind (AF_INET6, "*:5555", "::", 5555, "::");
}

static void test_resolve_ipv4_connect_any ()
{
    //  Cannot use wildcard for connection
    test_resolve_connect (AF_INET, "*:5555", NULL);
}

static void test_resolve_ipv6_connect_any ()
{
    //  Cannot use wildcard for connection
    test_resolve_connect (AF_INET6, "*:5555", NULL);
}

static void test_resolve_ipv4_connect_anyport ()
{
    test_resolve_connect (AF_INET, "127.0.0.1:*", NULL);
}

static void test_resolve_ipv6_connect_anyport ()
{
    test_resolve_connect (AF_INET6, "[::1]:*", NULL);
}

static void test_resolve_ipv4_connect_port0 ()
{
    test_resolve_connect (AF_INET, "127.0.0.1:0", "127.0.0.1", 0);
}

static void test_resolve_ipv6_connect_port0 ()
{
    test_resolve_connect (AF_INET6, "[2000:abcd::1]:0", "2000:abcd::1", 0);
}

static void test_resolve_ipv4_bind_mcast ()
{
    test_resolve_bind (AF_INET, "239.0.0.1:1234", "239.0.0.1", 1234, "0.0.0.0",
                       true);
}

static void test_resolve_ipv6_bind_mcast ()
{
    test_resolve_bind (AF_INET6, "[ff00::1]:1234", "ff00::1", 1234, "::", true);
}

static void test_resolve_ipv4_connect_mcast ()
{
    test_resolve_connect (AF_INET, "239.0.0.1:2222", "239.0.0.1", 2222, NULL,
                          true);
}

static void test_resolve_ipv6_connect_mcast ()
{
    test_resolve_connect (AF_INET6, "[ff00::1]:2222", "ff00::1", 2222, NULL,
                          true);
}

static void test_resolve_ipv4_mcast_src_bind ()
{
    test_resolve_bind (AF_INET, "127.0.0.1;230.2.8.12:5555", "230.2.8.12", 5555,
                       "127.0.0.1", true);
}

static void test_resolve_ipv6_mcast_src_bind ()
{
    if (!is_ipv6_available ()) {
        TEST_IGNORE_MESSAGE ("ipv6 is not available");
    }

    zmq::udp_address_t addr;
    int rc = addr.resolve ("[::1];[ffab::4]:5555", true, true);

    //  For the time being this fails because we only support binding multicast
    //  by interface name, not interface IP
    TEST_ASSERT_EQUAL (-1, rc);
    TEST_ASSERT_EQUAL (ENODEV, errno);
}

static void test_resolve_ipv4_mcast_src_bind_any ()
{
    test_resolve_bind (AF_INET, "*;230.2.8.12:5555", "230.2.8.12", 5555,
                       "0.0.0.0", true);
}

static void test_resolve_ipv6_mcast_src_bind_any ()
{
    test_resolve_bind (AF_INET6, "*;[ffff::]:5555", "ffff::", 5555, "::", true);
}

static void test_resolve_ipv4_mcast_src_connect ()
{
    test_resolve_connect (AF_INET, "8.9.10.11;230.2.8.12:5555", "230.2.8.12",
                          5555, "8.9.10.11", true);
}

static void test_resolve_ipv6_mcast_src_connect ()
{
    if (!is_ipv6_available ()) {
        TEST_IGNORE_MESSAGE ("ipv6 is not available");
    }

    zmq::udp_address_t addr;
    int rc = addr.resolve ("[1:2:3::4];[ff01::1]:5555", false, true);

    //  For the time being this fails because we only support binding multicast
    //  by interface name, not interface IP
    TEST_ASSERT_EQUAL (-1, rc);
    TEST_ASSERT_EQUAL (ENODEV, errno);
}

static void test_resolve_ipv4_mcast_src_connect_any ()
{
    test_resolve_connect (AF_INET, "*;230.2.8.12:5555", "230.2.8.12", 5555,
                          "0.0.0.0", true);
}

static void test_resolve_ipv6_mcast_src_connect_any ()
{
    test_resolve_connect (AF_INET6, "*;[ff10::1]:5555", "ff10::1", 5555,
                          "::", true);
}

static void test_resolve_ipv4_mcast_src_bind_bad ()
{
    test_resolve_bind (AF_INET, "127.0.0.1;1.2.3.4:5555", NULL);
}

static void test_resolve_ipv6_mcast_src_bind_bad ()
{
    test_resolve_bind (AF_INET6, "[::1];[fe00::1]:5555", NULL);
}

static void test_resolve_ipv4_mcast_src_connect_bad ()
{
    test_resolve_connect (AF_INET, "127.0.0.1;1.2.3.4:5555", NULL);
}

static void test_resolve_ipv6_mcast_src_connect_bad ()
{
    test_resolve_connect (AF_INET6, "[::1];[fe00:1]:5555", NULL);
}

int main (void)
{
    zmq::initialize_network ();
    setup_test_environment ();

    UNITY_BEGIN ();

    RUN_TEST (test_resolve_ipv4_simple);
    RUN_TEST (test_resolve_ipv6_simple);
    RUN_TEST (test_resolve_ipv4_bind);
    RUN_TEST (test_resolve_ipv6_bind);
    RUN_TEST (test_resolve_ipv4_bind_any);
    RUN_TEST (test_resolve_ipv6_bind_any);
    RUN_TEST (test_resolve_ipv4_bind_anyport);
    RUN_TEST (test_resolve_ipv6_bind_anyport);
    RUN_TEST (test_resolve_ipv4_bind_any_port);
    RUN_TEST (test_resolve_ipv6_bind_any_port);
    RUN_TEST (test_resolve_ipv4_connect_any);
    RUN_TEST (test_resolve_ipv6_connect_any);
    RUN_TEST (test_resolve_ipv4_connect_anyport);
    RUN_TEST (test_resolve_ipv6_connect_anyport);
    RUN_TEST (test_resolve_ipv4_connect_port0);
    RUN_TEST (test_resolve_ipv6_connect_port0);
    RUN_TEST (test_resolve_ipv4_bind_mcast);
    RUN_TEST (test_resolve_ipv6_bind_mcast);
    RUN_TEST (test_resolve_ipv4_connect_mcast);
    RUN_TEST (test_resolve_ipv6_connect_mcast);
    RUN_TEST (test_resolve_ipv4_mcast_src_bind);
    RUN_TEST (test_resolve_ipv6_mcast_src_bind);
    RUN_TEST (test_resolve_ipv4_mcast_src_bind_any);
    RUN_TEST (test_resolve_ipv6_mcast_src_bind_any);
    RUN_TEST (test_resolve_ipv4_mcast_src_connect);
    RUN_TEST (test_resolve_ipv6_mcast_src_connect);
    RUN_TEST (test_resolve_ipv4_mcast_src_connect_any);
    RUN_TEST (test_resolve_ipv6_mcast_src_connect_any);
    RUN_TEST (test_resolve_ipv4_mcast_src_bind_bad);
    RUN_TEST (test_resolve_ipv6_mcast_src_bind_bad);
    RUN_TEST (test_resolve_ipv4_mcast_src_connect_bad);
    RUN_TEST (test_resolve_ipv6_mcast_src_connect_bad);

    zmq::shutdown_network ();

    return UNITY_END ();
}
