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

#include <string.h>

SETUP_TEARDOWN_TESTCONTEXT

void ffn (void *data_, void *hint_)
{
    // Signal that ffn has been called by writing "freed" to hint
    (void) data_; //  Suppress 'unused' warnings at compile time
    memcpy (hint_, (void *) "freed", 5);
}

void test_msg_ffn ()
{
    //  Create the infrastructure
    char my_endpoint[MAX_SOCKET_STRING];

    void *router = test_context_socket (ZMQ_ROUTER);
    bind_loopback_ipv4 (router, my_endpoint, sizeof my_endpoint);

    void *dealer = test_context_socket (ZMQ_DEALER);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (dealer, my_endpoint));

    // Test that creating and closing a message triggers ffn
    zmq_msg_t msg;
    char hint[5];
    char data[255];
    memset (data, 0, 255);
    memcpy (data, (void *) "data", 4);
    memcpy (hint, (void *) "hint", 4);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_msg_init_data (&msg, (void *) data, 255, ffn, (void *) hint));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg));

    msleep (SETTLE_TIME);
    TEST_ASSERT_EQUAL_STRING_LEN ("freed", hint, 5);
    memcpy (hint, (void *) "hint", 4);

    // Making and closing a copy triggers ffn
    zmq_msg_t msg2;
    zmq_msg_init (&msg2);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_msg_init_data (&msg, (void *) data, 255, ffn, (void *) hint));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_copy (&msg2, &msg));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg2));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg));

    msleep (SETTLE_TIME);
    TEST_ASSERT_EQUAL_STRING_LEN ("freed", hint, 5);
    memcpy (hint, (void *) "hint", 4);

    // Test that sending a message triggers ffn
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_msg_init_data (&msg, (void *) data, 255, ffn, (void *) hint));

    zmq_msg_send (&msg, dealer, 0);
    char buf[255];
    TEST_ASSERT_SUCCESS_ERRNO (zmq_recv (router, buf, 255, 0));
    TEST_ASSERT_EQUAL_INT (255, zmq_recv (router, buf, 255, 0));
    TEST_ASSERT_EQUAL_STRING_LEN (data, buf, 4);

    msleep (SETTLE_TIME);
    TEST_ASSERT_EQUAL_STRING_LEN ("freed", hint, 5);
    memcpy (hint, (void *) "hint", 4);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg));

    // Sending a copy of a message triggers ffn
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init (&msg2));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_msg_init_data (&msg, (void *) data, 255, ffn, (void *) hint));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_copy (&msg2, &msg));

    zmq_msg_send (&msg, dealer, 0);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_recv (router, buf, 255, 0));
    TEST_ASSERT_EQUAL_INT (255, zmq_recv (router, buf, 255, 0));
    TEST_ASSERT_EQUAL_STRING_LEN (data, buf, 4);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg2));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg));

    msleep (SETTLE_TIME);
    TEST_ASSERT_EQUAL_STRING_LEN ("freed", hint, 5);

    //  Deallocate the infrastructure.
    test_context_socket_close (router);
    test_context_socket_close (dealer);
}

int main (void)
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_msg_ffn);
    return UNITY_END ();
}
