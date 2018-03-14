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

#include <unity.h>

void setUp ()
{
    setup_test_context ();
}

void tearDown ()
{
    teardown_test_context ();
}

void test_x ()
{
    const char *bind_to = "tcp://127.0.0.1:*";
    size_t len = MAX_SOCKET_STRING;
    char my_endpoint[MAX_SOCKET_STRING];

    int rc;

    void *s_in = test_context_socket (ZMQ_PULL);

    int conflate = 1;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (s_in, ZMQ_CONFLATE, &conflate, sizeof (conflate)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (s_in, bind_to));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (s_in, ZMQ_LAST_ENDPOINT, my_endpoint, &len));

    void *s_out = test_context_socket (ZMQ_PUSH);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (s_out, my_endpoint));

    int message_count = 20;
    for (int j = 0; j < message_count; ++j) {
        TEST_ASSERT_SUCCESS_ERRNO (
          zmq_send (s_out, (void *) &j, sizeof (int), 0));
    }
    msleep (SETTLE_TIME);

    int payload_recved = 0;
    rc = TEST_ASSERT_SUCCESS_ERRNO (
      zmq_recv (s_in, (void *) &payload_recved, sizeof (int), 0));
    TEST_ASSERT_GREATER_THAN_INT (0, rc);
    TEST_ASSERT_EQUAL_INT (message_count - 1, payload_recved);

    test_context_socket_close (s_in);
    test_context_socket_close (s_out);
}

int main (int, char *[])
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_x);
    return UNITY_END ();
}
