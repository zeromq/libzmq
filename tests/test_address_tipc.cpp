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
#include <unity.h>


void setUp ()
{
}
void tearDown ()
{
}

void test_tipc_port_name_and_domain ()
{
    void *ctx = zmq_ctx_new ();
    TEST_ASSERT_NOT_NULL (ctx);

    // test Port Name addressing
    void *sb = zmq_socket (ctx, ZMQ_REP);
    TEST_ASSERT_NOT_NULL (sb);
    int rc = zmq_bind (sb, "tipc://{5560,0,0}");
    TEST_ASSERT_EQUAL_INT (0, rc);

    void *sc = zmq_socket (ctx, ZMQ_REQ);
    TEST_ASSERT_NOT_NULL (sc);
    rc = zmq_connect (sc, "tipc://{5560,0}@0.0.0");
    TEST_ASSERT_EQUAL_INT (0, rc);

    bounce (sb, sc);

    rc = zmq_close (sc);
    TEST_ASSERT_EQUAL_INT (0, rc);

    rc = zmq_close (sb);
    TEST_ASSERT_EQUAL_INT (0, rc);

    zmq_ctx_term (ctx);
}

void test_tipc_port_identity ()
{
    char endpoint[256];
    size_t size = 256;
    unsigned int z, c, n, ref;

    void *ctx = zmq_ctx_new ();
    TEST_ASSERT_NOT_NULL (ctx);

    void *sb = zmq_socket (ctx, ZMQ_REP);
    TEST_ASSERT_NOT_NULL (sb);

    void *sc = zmq_socket (ctx, ZMQ_REQ);
    TEST_ASSERT_NOT_NULL (sc);

    // Test binding to random Port Identity
    int rc = zmq_bind (sb, "tipc://<*>");
    TEST_ASSERT_EQUAL_INT (0, rc);

    // Test resolving assigned address, should return a properly formatted string
    rc = zmq_getsockopt (sb, ZMQ_LAST_ENDPOINT, &endpoint[0], &size);
    TEST_ASSERT_EQUAL_INT (0, rc);

    rc = sscanf (&endpoint[0], "tipc://<%u.%u.%u:%u>", &z, &c, &n, &ref);
    TEST_ASSERT_EQUAL_INT (4, rc);

    TEST_ASSERT_NOT_EQUAL_MESSAGE (
      0, ref, "tipc port number must not be 0 after random assignment");

    rc = zmq_connect (sc, endpoint);
    TEST_ASSERT_EQUAL_INT (0, rc);

    bounce (sb, sc);

    rc = zmq_close (sc);
    TEST_ASSERT_EQUAL_INT (0, rc);

    rc = zmq_close (sb);
    TEST_ASSERT_EQUAL_INT (0, rc);

    zmq_ctx_term (ctx);
}

void test_tipc_bad_addresses ()
{
    void *ctx = zmq_ctx_new ();
    TEST_ASSERT_NOT_NULL (ctx);

    // Test Port Name addressing
    void *sb = zmq_socket (ctx, ZMQ_REP);
    TEST_ASSERT_NOT_NULL (sb);

    // Test binding to a fixed address, should fail
    int rc = zmq_bind (sb, "tipc://<1.2.3:123123>");
    TEST_ASSERT_EQUAL_INT (-1, rc);
    TEST_ASSERT_EQUAL_INT (EINVAL, errno);

    // Test connecting to random identity, should fail
    rc = zmq_connect (sb, "tipc://<*>");
    TEST_ASSERT_EQUAL_INT (-1, rc);
    TEST_ASSERT_EQUAL_INT (EINVAL, errno);

    // Clean up
    rc = zmq_close (sb);
    TEST_ASSERT_EQUAL_INT (0, rc);

    zmq_ctx_term (ctx);
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
