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

static void pusher (void * /*unused*/)
{
    // Connect first
    // do not use test_context_socket here, as it is not thread-safe
    void *connect_socket = zmq_socket (get_test_context (), ZMQ_PAIR);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (connect_socket, "inproc://sink"));

    // Queue up some data
    send_string_expect_success (connect_socket, "foobar", 0);

    // Cleanup
    TEST_ASSERT_SUCCESS_ERRNO (zmq_close (connect_socket));
}

static void simult_conn (void *endpt_)
{
    // Pull out arguments - endpoint string
    const char *endpt = static_cast<const char *> (endpt_);

    // Connect
    // do not use test_context_socket here, as it is not thread-safe
    void *connect_socket = zmq_socket (get_test_context (), ZMQ_SUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (connect_socket, endpt));

    // Cleanup
    TEST_ASSERT_SUCCESS_ERRNO (zmq_close (connect_socket));
}

static void simult_bind (void *endpt_)
{
    // Pull out arguments - context followed by endpoint string
    const char *endpt = static_cast<const char *> (endpt_);

    // Bind
    // do not use test_context_socket here, as it is not thread-safe
    void *bind_socket = zmq_socket (get_test_context (), ZMQ_PUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (bind_socket, endpt));

    // Cleanup
    TEST_ASSERT_SUCCESS_ERRNO (zmq_close (bind_socket));
}

void test_bind_before_connect ()
{
    // Bind first
    void *bind_socket = test_context_socket (ZMQ_PAIR);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (bind_socket, "inproc://bbc"));

    // Now connect
    void *connect_socket = test_context_socket (ZMQ_PAIR);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (connect_socket, "inproc://bbc"));

    // Queue up some data
    send_string_expect_success (connect_socket, "foobar", 0);

    // Read pending message
    recv_string_expect_success (bind_socket, "foobar", 0);

    // Cleanup
    test_context_socket_close (connect_socket);
    test_context_socket_close (bind_socket);
}

void test_connect_before_bind ()
{
    // Connect first
    void *connect_socket = test_context_socket (ZMQ_PAIR);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (connect_socket, "inproc://cbb"));

    // Queue up some data
    send_string_expect_success (connect_socket, "foobar", 0);

    // Now bind
    void *bind_socket = test_context_socket (ZMQ_PAIR);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (bind_socket, "inproc://cbb"));

    // Read pending message
    recv_string_expect_success (bind_socket, "foobar", 0);

    // Cleanup
    test_context_socket_close (connect_socket);
    test_context_socket_close (bind_socket);
}

void test_connect_before_bind_pub_sub ()
{
    // Connect first
    void *connect_socket = test_context_socket (ZMQ_PUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (connect_socket, "inproc://cbbps"));

    // Queue up some data, this will be dropped
    send_string_expect_success (connect_socket, "before", 0);

    // Now bind
    void *bind_socket = test_context_socket (ZMQ_SUB);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (bind_socket, ZMQ_SUBSCRIBE, "", 0));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (bind_socket, "inproc://cbbps"));

    // Wait for pub-sub connection to happen
    msleep (SETTLE_TIME);

    // Queue up some data, this not will be dropped
    send_string_expect_success (connect_socket, "after", 0);

    // Read pending message
    recv_string_expect_success (bind_socket, "after", 0);

    // Cleanup
    test_context_socket_close (connect_socket);
    test_context_socket_close (bind_socket);
}

void test_connect_before_bind_ctx_term ()
{
    for (int i = 0; i < 20; ++i) {
        // Connect first
        void *connect_socket = test_context_socket (ZMQ_ROUTER);

        char ep[32];
        sprintf (ep, "inproc://cbbrr%d", i);
        TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (connect_socket, ep));

        // Cleanup
        test_context_socket_close (connect_socket);
    }
}

void test_multiple_connects ()
{
    const unsigned int no_of_connects = 10;

    void *connect_socket[no_of_connects];

    // Connect first
    for (unsigned int i = 0; i < no_of_connects; ++i) {
        connect_socket[i] = test_context_socket (ZMQ_PUSH);
        TEST_ASSERT_SUCCESS_ERRNO (
          zmq_connect (connect_socket[i], "inproc://multiple"));

        // Queue up some data
        send_string_expect_success (connect_socket[i], "foobar", 0);
    }

    // Now bind
    void *bind_socket = test_context_socket (ZMQ_PULL);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (bind_socket, "inproc://multiple"));

    for (unsigned int i = 0; i < no_of_connects; ++i) {
        recv_string_expect_success (bind_socket, "foobar", 0);
    }

    // Cleanup
    for (unsigned int i = 0; i < no_of_connects; ++i) {
        test_context_socket_close (connect_socket[i]);
    }

    test_context_socket_close (bind_socket);
}

void test_multiple_threads ()
{
    const unsigned int no_of_threads = 30;

    void *threads[no_of_threads];

    // Connect first
    for (unsigned int i = 0; i < no_of_threads; ++i) {
        threads[i] = zmq_threadstart (&pusher, NULL);
    }

    // Now bind
    void *bind_socket = test_context_socket (ZMQ_PULL);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (bind_socket, "inproc://sink"));

    for (unsigned int i = 0; i < no_of_threads; ++i) {
        // Read pending message
        recv_string_expect_success (bind_socket, "foobar", 0);
    }

    // Cleanup
    for (unsigned int i = 0; i < no_of_threads; ++i) {
        zmq_threadclose (threads[i]);
    }

    test_context_socket_close (bind_socket);
}

void test_simultaneous_connect_bind_threads ()
{
    const unsigned int no_of_times = 50;
    void *threads[no_of_times * 2];
    void *thr_args[no_of_times];
    char endpts[no_of_times][20];

    // Set up thread arguments: context followed by endpoint string
    for (unsigned int i = 0; i < no_of_times; ++i) {
        thr_args[i] = (void *) endpts[i];
        sprintf (endpts[i], "inproc://foo_%d", i);
    }

    // Spawn all threads as simultaneously as possible
    for (unsigned int i = 0; i < no_of_times; ++i) {
        threads[i * 2 + 0] =
          zmq_threadstart (&simult_conn, (void *) thr_args[i]);
        threads[i * 2 + 1] =
          zmq_threadstart (&simult_bind, (void *) thr_args[i]);
    }

    // Close all threads
    for (unsigned int i = 0; i < no_of_times; ++i) {
        zmq_threadclose (threads[i * 2 + 0]);
        zmq_threadclose (threads[i * 2 + 1]);
    }
}

void test_routing_id ()
{
    //  Create the infrastructure
    void *sc = test_context_socket (ZMQ_DEALER);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc, "inproc://routing_id"));

    void *sb = test_context_socket (ZMQ_ROUTER);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (sb, "inproc://routing_id"));

    //  Send 2-part message.
    TEST_ASSERT_EQUAL_INT (
      1, TEST_ASSERT_SUCCESS_ERRNO (zmq_send (sc, "A", 1, ZMQ_SNDMORE)));
    TEST_ASSERT_EQUAL_INT (
      1, TEST_ASSERT_SUCCESS_ERRNO (zmq_send (sc, "B", 1, 0)));

    //  Routing id comes first.
    zmq_msg_t msg;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init (&msg));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_recv (&msg, sb, 0));
    TEST_ASSERT_EQUAL_INT (1, zmq_msg_more (&msg));

    //  Then the first part of the message body.
    TEST_ASSERT_EQUAL_INT (
      1, TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_recv (&msg, sb, 0)));
    TEST_ASSERT_EQUAL_INT (1, zmq_msg_more (&msg));

    //  And finally, the second part of the message body.
    TEST_ASSERT_EQUAL_INT (
      1, TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_recv (&msg, sb, 0)));
    TEST_ASSERT_EQUAL_INT (0, zmq_msg_more (&msg));

    //  Deallocate the infrastructure.
    test_context_socket_close (sc);
    test_context_socket_close (sb);
}

void test_connect_only ()
{
    void *connect_socket = test_context_socket (ZMQ_PUSH);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (connect_socket, "inproc://a"));

    test_context_socket_close (connect_socket);
}


void test_unbind ()
{
    // Bind and unbind socket 1
    void *bind_socket1 = test_context_socket (ZMQ_PAIR);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (bind_socket1, "inproc://unbind"));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_unbind (bind_socket1, "inproc://unbind"));

    // Bind socket 2
    void *bind_socket2 = test_context_socket (ZMQ_PAIR);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (bind_socket2, "inproc://unbind"));

    // Now connect
    void *connect_socket = test_context_socket (ZMQ_PAIR);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (connect_socket, "inproc://unbind"));

    // Queue up some data
    send_string_expect_success (connect_socket, "foobar", 0);

    // Read pending message
    recv_string_expect_success (bind_socket2, "foobar", 0);

    // Cleanup
    test_context_socket_close (connect_socket);
    test_context_socket_close (bind_socket1);
    test_context_socket_close (bind_socket2);
}

void test_shutdown_during_pend ()
{
    // Connect first
    void *connect_socket = test_context_socket (ZMQ_PAIR);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (connect_socket, "inproc://cbb"));

    zmq_ctx_shutdown (get_test_context ());

    // Cleanup
    test_context_socket_close (connect_socket);
}

int main (void)
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_bind_before_connect);
    RUN_TEST (test_connect_before_bind);
    RUN_TEST (test_connect_before_bind_pub_sub);
    RUN_TEST (test_connect_before_bind_ctx_term);
    RUN_TEST (test_multiple_connects);
    RUN_TEST (test_multiple_threads);
    RUN_TEST (test_simultaneous_connect_bind_threads);
    RUN_TEST (test_routing_id);
    RUN_TEST (test_connect_only);
    RUN_TEST (test_unbind);
    RUN_TEST (test_shutdown_during_pend);
    return UNITY_END ();
}
