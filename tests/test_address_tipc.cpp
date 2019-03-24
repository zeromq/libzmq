/*
    Copyright (c) 2007-2018 Contributors as noted in the AUTHORS file

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

void test_tipc_port_name_and_domain ()
{
    // test Port Name addressing
    void *sb = test_context_socket (ZMQ_REP);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (sb, "tipc://{5560,0,0}"));

    void *sc = test_context_socket (ZMQ_REQ);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc, "tipc://{5560,0}@0.0.0"));

    bounce (sb, sc);

    test_context_socket_close (sc);
    test_context_socket_close (sb);
}

void test_tipc_port_identity ()
{
    char endpoint[256];
    unsigned int z, c, n, ref;

    void *sb = test_context_socket (ZMQ_REP);
    void *sc = test_context_socket (ZMQ_REQ);

    // Test binding to random Port Identity and
    // test resolving assigned address, should return a properly formatted string
    bind_loopback_tipc (sb, endpoint, sizeof endpoint);

    int rc = sscanf (&endpoint[0], "tipc://<%u.%u.%u:%u>", &z, &c, &n, &ref);
    TEST_ASSERT_EQUAL_INT (4, rc);

    TEST_ASSERT_NOT_EQUAL_MESSAGE (
      0, ref, "tipc port number must not be 0 after random assignment");

    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc, endpoint));

    bounce (sb, sc);

    test_context_socket_close (sc);
    test_context_socket_close (sb);
}

void test_tipc_bad_addresses ()
{
    // Test Port Name addressing
    void *sb = test_context_socket (ZMQ_REP);

    // Test binding to a fixed address, should fail
    TEST_ASSERT_FAILURE_ERRNO (EINVAL, zmq_bind (sb, "tipc://<1.2.3:123123>"));

    // Test connecting to random identity, should fail
    TEST_ASSERT_FAILURE_ERRNO (EINVAL, zmq_connect (sb, "tipc://<*>"));

    // Clean up
    test_context_socket_close (sb);
}


int main ()
{
    setup_test_environment ();

    if (!is_tipc_available ()) {
        printf ("TIPC environment unavailable, skipping test\n");
        return 77;
    }

    UNITY_BEGIN ();
    RUN_TEST (test_tipc_port_name_and_domain);
    RUN_TEST (test_tipc_port_identity);
    RUN_TEST (test_tipc_bad_addresses);

    return UNITY_END ();
}
