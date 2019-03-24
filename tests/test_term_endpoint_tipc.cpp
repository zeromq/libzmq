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

const char ep[] = "tipc://{5560,0,0}";
const char name[] = "tipc://{5560,0}@0.0.0";

void test_term_endpoint_unbind_tipc ()
{
    if (!is_tipc_available ()) {
        TEST_IGNORE_MESSAGE ("TIPC environment unavailable, skipping test\n");
    }

    //  Create infrastructure.
    void *push = test_context_socket (ZMQ_PUSH);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (push, ep));
    void *pull = test_context_socket (ZMQ_PULL);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (pull, name));

    //  Pass one message through to ensure the connection is established.
    send_string_expect_success (push, "ABC", 0);
    recv_string_expect_success (pull, "ABC", 0);

    // Unbind the lisnening endpoint
    TEST_ASSERT_SUCCESS_ERRNO (zmq_unbind (push, ep));

    // Let events some time
    msleep (SETTLE_TIME);

    //  Check that sending would block (there's no outbound connection).
    TEST_ASSERT_FAILURE_ERRNO (EAGAIN, zmq_send (push, "ABC", 3, ZMQ_DONTWAIT));

    //  Clean up.
    test_context_socket_close (pull);
    test_context_socket_close (push);
}

void test_term_endpoint_disconnect_tipc ()
{
    if (!is_tipc_available ()) {
        TEST_IGNORE_MESSAGE ("TIPC environment unavailable, skipping test\n");
    }

    //  Create infrastructure.
    void *push = test_context_socket (ZMQ_PUSH);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (push, name));
    void *pull = test_context_socket (ZMQ_PULL);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (pull, ep));

    //  Pass one message through to ensure the connection is established.
    send_string_expect_success (push, "ABC", 0);
    recv_string_expect_success (pull, "ABC", 0);

    // Disconnect the bound endpoint
    TEST_ASSERT_SUCCESS_ERRNO (zmq_disconnect (push, name));

    msleep (SETTLE_TIME);

    //  Check that sending would block (there's no inbound connections).
    TEST_ASSERT_FAILURE_ERRNO (EAGAIN, zmq_send (push, "ABC", 3, ZMQ_DONTWAIT));

    //  Clean up.
    test_context_socket_close (pull);
    test_context_socket_close (push);
}

int main (void)
{
    UNITY_BEGIN ();
    RUN_TEST (test_term_endpoint_unbind_tipc);
    RUN_TEST (test_term_endpoint_disconnect_tipc);
    return UNITY_END ();
}
