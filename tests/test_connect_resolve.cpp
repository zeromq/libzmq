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

#include "testutil.hpp"

#include "testutil_unity.hpp"

#include <unity.h>

void *sock;

void setUp ()
{
    setup_test_context ();
    sock = test_context_socket (ZMQ_PUB);
}

void tearDown ()
{
    test_context_socket_close (sock);
    sock = NULL;
    teardown_test_context ();
}

void test_hostname_ipv4 ()
{
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sock, "tcp://localhost:1234"));
}

void test_loopback_ipv6 ()
{
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sock, "tcp://[::1]:1234"));
}

void test_invalid_service_fails ()
{
    int rc = zmq_connect (sock, "tcp://localhost:invalid");
    TEST_ASSERT_EQUAL_INT (-1, rc);
}

void test_hostname_with_spaces_fails ()
{
    int rc = zmq_connect (sock, "tcp://in val id:1234");
    TEST_ASSERT_EQUAL_INT (-1, rc);
}

void test_no_hostname_fails ()
{
    int rc = zmq_connect (sock, "tcp://");
    TEST_ASSERT_EQUAL_INT (-1, rc);
}

void test_x ()
{
    int rc = zmq_connect (sock, "tcp://192.168.0.200:*");
    TEST_ASSERT_EQUAL_INT (-1, rc);
}

void test_invalid_proto_fails ()
{
    int rc = zmq_connect (sock, "invalid://localhost:1234");
    TEST_ASSERT_EQUAL_INT (-1, rc);
    TEST_ASSERT_EQUAL_INT (EPROTONOSUPPORT, errno);
}

int main (void)
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_hostname_ipv4);
    RUN_TEST (test_loopback_ipv6);
    RUN_TEST (test_hostname_with_spaces_fails);
    RUN_TEST (test_no_hostname_fails);
    RUN_TEST (test_invalid_service_fails);
    RUN_TEST (test_invalid_proto_fails);
    return UNITY_END ();
}
