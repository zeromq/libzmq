/*
    Copyright (c) 2007-2017 Contributors as noted in the AUTHORS file

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

SETUP_TEARDOWN_TESTCONTEXT

void test_no_zap_handler ()
{
    //  We first test client/server with a ZAP domain but with no handler
    //  If there is no handler, libzmq should ignore the ZAP option unless
    //  ZMQ_ZAP_ENFORCE_DOMAIN is set
    void *server = test_context_socket (ZMQ_DEALER);
    void *client = test_context_socket (ZMQ_DEALER);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (server, ZMQ_ZAP_DOMAIN, "TEST", 5));
    char my_endpoint[MAX_SOCKET_STRING];
    bind_loopback_ipv4 (server, my_endpoint, sizeof my_endpoint);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (client, my_endpoint));
    bounce (server, client);
    test_context_socket_close_zero_linger (client);
    test_context_socket_close_zero_linger (server);
}

void test_no_zap_handler_enforce_domain ()
{
#ifdef ZMQ_ZAP_ENFORCE_DOMAIN
    //  Now set ZMQ_ZAP_ENFORCE_DOMAIN which strictly enforces the ZAP
    //  RFC but is backward-incompatible, now it should fail
    void *server = test_context_socket (ZMQ_DEALER);
    void *client = test_context_socket (ZMQ_DEALER);
    int required = 1;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (server, ZMQ_ZAP_ENFORCE_DOMAIN, &required, sizeof (int)));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (server, ZMQ_ZAP_DOMAIN, "TEST", 5));
    char my_endpoint[MAX_SOCKET_STRING];
    bind_loopback_ipv4 (server, my_endpoint, sizeof my_endpoint);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (client, my_endpoint));
    expect_bounce_fail (server, client);
    test_context_socket_close_zero_linger (client);
    test_context_socket_close_zero_linger (server);
#endif
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_no_zap_handler);
    RUN_TEST (test_no_zap_handler_enforce_domain);
    return UNITY_END ();
}
