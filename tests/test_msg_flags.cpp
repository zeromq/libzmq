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

SETUP_TEARDOWN_TESTCONTEXT

void test_more ()
{
    //  Create the infrastructure
    void *sb = test_context_socket (ZMQ_ROUTER);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (sb, "inproc://a"));

    void *sc = test_context_socket (ZMQ_DEALER);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc, "inproc://a"));

    //  Send 2-part message.
    send_string_expect_success (sc, "A", ZMQ_SNDMORE);
    send_string_expect_success (sc, "B", 0);

    //  Routing id comes first.
    zmq_msg_t msg;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init (&msg));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_recv (&msg, sb, 0));
    TEST_ASSERT_EQUAL_INT (1, TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_more (&msg)));

    //  Then the first part of the message body.
    TEST_ASSERT_EQUAL_INT (
      1, TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_recv (&msg, sb, 0)));
    TEST_ASSERT_EQUAL_INT (1, TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_more (&msg)));

    //  And finally, the second part of the message body.
    TEST_ASSERT_EQUAL_INT (
      1, TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_recv (&msg, sb, 0)));
    TEST_ASSERT_EQUAL_INT (0, TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_more (&msg)));

    //  Deallocate the infrastructure.
    test_context_socket_close (sc);
    test_context_socket_close (sb);
}

void test_shared_refcounted ()
{
    // Test ZMQ_SHARED property (case 1, refcounted messages)
    zmq_msg_t msg_a;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_msg_init_size (&msg_a, 1024)); // large enough to be a type_lmsg

    // Message is not shared
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_get (&msg_a, ZMQ_SHARED));

    zmq_msg_t msg_b;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init (&msg_b));

    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_copy (&msg_b, &msg_a));

    // Message is now shared
    TEST_ASSERT_EQUAL_INT (
      1, TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_get (&msg_b, ZMQ_SHARED)));

    // cleanup
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg_a));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg_b));
}

void test_shared_const ()
{
    zmq_msg_t msg_a;
    // Test ZMQ_SHARED property (case 2, constant data messages)
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_msg_init_data (&msg_a, (void *) "TEST", 5, 0, 0));

    // Message reports as shared
    TEST_ASSERT_EQUAL_INT (
      1, TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_get (&msg_a, ZMQ_SHARED)));

    // cleanup
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg_a));
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_more);
    RUN_TEST (test_shared_refcounted);
    RUN_TEST (test_shared_const);
    return UNITY_END ();
}
