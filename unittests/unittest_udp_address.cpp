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
static void test_resolve (bool bind_, const char *name_, const char *dest_addr_,
                          uint16_t expected_port_,
                          const char *bind_addr_,
                          bool multicast_)
{
    zmq::udp_address_t addr;

    int rc = addr.resolve (name_, bind_);

    if (dest_addr_ == NULL) {
        TEST_ASSERT_EQUAL (-1, rc);
        TEST_ASSERT_EQUAL (EINVAL, errno);
        return;
    } else {
        TEST_ASSERT_EQUAL (0, rc);
    }

    TEST_ASSERT_EQUAL (multicast_, addr.is_mcast ());

    struct sockaddr_in *dest = (struct sockaddr_in *)addr.dest_addr ();
    struct in_addr expected_dest;
    assert (test_inet_pton (AF_INET, dest_addr_, &expected_dest) == 1);

    TEST_ASSERT_EQUAL (AF_INET, dest->sin_family);
    TEST_ASSERT_EQUAL (expected_dest.s_addr, dest->sin_addr.s_addr);
    TEST_ASSERT_EQUAL (htons (expected_port_), dest->sin_port);

    struct sockaddr_in *bind = (struct sockaddr_in *)addr.bind_addr ();
    struct in_addr expected_bind;

    if (bind_addr_ == NULL) {
        // Bind ANY
        bind_addr_ = "0.0.0.0";
    }

    assert (test_inet_pton (AF_INET, bind_addr_, &expected_bind) == 1);

    TEST_ASSERT_EQUAL (AF_INET, bind->sin_family);
    TEST_ASSERT_EQUAL (expected_bind.s_addr, bind->sin_addr.s_addr);
    TEST_ASSERT_EQUAL (htons (expected_port_), bind->sin_port);
}

static void test_resolve_bind (const char *name_, const char *dest_addr_,
                               uint16_t expected_port_ = 0,
                               const char *bind_addr_ = NULL,
                               bool multicast_ = false)
{
    test_resolve (true, name_, dest_addr_, expected_port_, bind_addr_,
                  multicast_);
}

static void test_resolve_connect (const char *name_, const char *dest_addr_,
                                  uint16_t expected_port_ = 0,
                                  const char *bind_addr_ = NULL,
                                  bool multicast_ = false)
{
    test_resolve (false, name_, dest_addr_, expected_port_, bind_addr_,
                  multicast_);
}

static void test_resolve_ipv4_simple ()
{
    test_resolve_connect ("127.0.0.1:5555", "127.0.0.1", 5555);
}

static void test_resolve_ipv4_bind ()
{
    test_resolve_bind ("127.0.0.1:5555", "127.0.0.1", 5555, "127.0.0.1");
}

static void test_resolve_ipv4_bind_any ()
{
    test_resolve_bind ("*:*", "0.0.0.0", 0, "0.0.0.0");
}

static void test_resolve_ipv4_bind_anyport ()
{
    test_resolve_bind ("127.0.0.1:*", "127.0.0.1", 0, "127.0.0.1");
}

static void test_resolve_ipv4_bind_any_port ()
{
    test_resolve_bind ("*:5555", "0.0.0.0", 5555, "0.0.0.0");
}

static void test_resolve_ipv4_connect_any ()
{
    //  Cannot use wildcard for connection
    test_resolve_connect ("*:5555", NULL);
}

static void test_resolve_ipv4_connect_anyport ()
{
    test_resolve_connect ("127.0.0.1:*", NULL);
}

static void test_resolve_ipv4_connect_port0 ()
{
    test_resolve_connect ("127.0.0.1:0", "127.0.0.1", 0);
}

static void test_resolve_ipv4_bind_mcast ()
{
    test_resolve_bind ("239.0.0.1:1234", "239.0.0.1", 1234, "0.0.0.0", true);
}

static void test_resolve_ipv4_connect_mcast ()
{
    test_resolve_connect ("239.0.0.1:2222", "239.0.0.1", 2222, NULL, true);
}

static void test_resolve_ipv6_simple ()
{
    if (!is_ipv6_available ()) {
        TEST_IGNORE_MESSAGE ("ipv6 is not available");
    }

    //  IPv6 not yet supported
    test_resolve_connect ("::1", NULL);
}

static void test_resolve_ipv4_mcast_src_bind ()
{
    test_resolve_bind ("127.0.0.1;230.2.8.12:5555", "230.2.8.12", 5555,
                       "127.0.0.1", true);
}

static void test_resolve_ipv4_mcast_src_bind_any ()
{
    test_resolve_bind ("*;230.2.8.12:5555", "230.2.8.12", 5555,
                       "0.0.0.0", true);
}

static void test_resolve_ipv4_mcast_src_connect ()
{
    test_resolve_connect ("8.9.10.11;230.2.8.12:5555", "230.2.8.12", 5555,
                          "8.9.10.11", true);
}

static void test_resolve_ipv4_mcast_src_connect_any ()
{
    test_resolve_connect ("*;230.2.8.12:5555", "230.2.8.12", 5555,
                          "0.0.0.0", true);
}

static void test_resolve_ipv4_mcast_src_bind_bad ()
{
    test_resolve_bind ("127.0.0.1;1.2.3.4:5555", NULL);
}

static void test_resolve_ipv4_mcast_src_connect_bad ()
{
    test_resolve_connect ("127.0.0.1;1.2.3.4:5555", NULL);
}

int main (void)
{
    zmq::initialize_network ();
    setup_test_environment ();

    UNITY_BEGIN ();

    RUN_TEST (test_resolve_ipv4_simple);
    RUN_TEST (test_resolve_ipv4_bind);
    RUN_TEST (test_resolve_ipv4_bind_any);
    RUN_TEST (test_resolve_ipv4_bind_anyport);
    RUN_TEST (test_resolve_ipv4_bind_any_port);
    RUN_TEST (test_resolve_ipv4_connect_any);
    RUN_TEST (test_resolve_ipv4_connect_anyport);
    RUN_TEST (test_resolve_ipv4_connect_port0);
    RUN_TEST (test_resolve_ipv4_bind_mcast);
    RUN_TEST (test_resolve_ipv4_connect_mcast);
    RUN_TEST (test_resolve_ipv6_simple);
    RUN_TEST (test_resolve_ipv4_mcast_src_bind);
    RUN_TEST (test_resolve_ipv4_mcast_src_bind_any);
    RUN_TEST (test_resolve_ipv4_mcast_src_connect);
    RUN_TEST (test_resolve_ipv4_mcast_src_connect_any);
    RUN_TEST (test_resolve_ipv4_mcast_src_bind_bad);
    RUN_TEST (test_resolve_ipv4_mcast_src_connect_bad);

    zmq::shutdown_network ();

    return UNITY_END ();
}
