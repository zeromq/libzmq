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

//  Test an UDP address resolution. If 'bind_addr_' is not NULL
//  request a bind address. If 'dest_addr_' is NULL assume the
//  resolution is supposed to fail.
static void test_resolve (const char *name_, const char *dest_addr_,
                          uint16_t expected_port_ = 0,
                          const char *bind_addr_ = NULL,
                          bool multicast_ = false)
{
    zmq::udp_address_t addr;
    bool bound = bind_addr_ != NULL;

    int rc = addr.resolve (name_, bound);

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

static void test_resolve_ipv4_simple ()
{
    test_resolve ("127.0.0.1:5555", "127.0.0.1", 5555);
}

static void test_resolve_ipv4_bind ()
{
    test_resolve ("127.0.0.1:5555", "127.0.0.1", 5555, "127.0.0.1");
}

static void test_resolve_ipv4_bind_any ()
{
    //  Wildcard port not supported
    test_resolve ("*:*", NULL, 0, "0.0.0.0");
}

static void test_resolve_ipv4_bind_anyport ()
{
    //  Wildcard port not supported
    test_resolve ("127.0.0.1:*", NULL, 0, "127.0.0.1");
}

static void test_resolve_ipv4_bind_any_port ()
{
    test_resolve ("*:5555", "0.0.0.0", 5555, "0.0.0.0");
}

static void test_resolve_ipv4_connect_any ()
{
    //  Cannot use wildcard for connection
    test_resolve ("*:5555", NULL);
}

static void test_resolve_ipv4_connect_anyport ()
{
    test_resolve ("127.0.0.1:*", NULL);
}

static void test_resolve_ipv4_bind_mcast ()
{
    test_resolve ("239.0.0.1:1234", "239.0.0.1", 1234, "0.0.0.0", true);
}

static void test_resolve_ipv4_connect_mcast ()
{
    test_resolve ("239.0.0.1:2222", "239.0.0.1", 2222, NULL, true);
}

static void test_resolve_ipv6_simple ()
{
    if (!is_ipv6_available ()) {
        TEST_IGNORE_MESSAGE ("ipv6 is not available");
    }

    //  IPv6 not yet supported
    test_resolve ("::1", NULL);
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
    RUN_TEST (test_resolve_ipv4_bind_mcast);
    RUN_TEST (test_resolve_ipv4_connect_mcast);
    RUN_TEST (test_resolve_ipv6_simple);

    zmq::shutdown_network ();

    return UNITY_END ();
}
