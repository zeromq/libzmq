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

const size_t services = 5;

void *req;
void *rep[services];

void setUp ()
{
    setup_test_context ();

    char my_endpoint[MAX_SOCKET_STRING];
    req = test_context_socket (ZMQ_REQ);

    int enabled = 1;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (req, ZMQ_REQ_RELAXED, &enabled, sizeof (int)));

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (req, ZMQ_REQ_CORRELATE, &enabled, sizeof (int)));

    bind_loopback_ipv4 (req, my_endpoint, sizeof (my_endpoint));

    for (size_t peer = 0; peer < services; peer++) {
        rep[peer] = test_context_socket (ZMQ_REP);

        TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (rep[peer], my_endpoint));

        //  These tests require strict ordering, so wait for the connections to
        //  happen before opening the next, so that messages flow in the
        //  expected direction
        msleep (SETTLE_TIME);
    }
}

void tearDown ()
{
    test_context_socket_close_zero_linger (req);
    for (size_t peer = 0; peer < services; peer++)
        test_context_socket_close_zero_linger (rep[peer]);

    teardown_test_context ();
}

static void bounce (void *socket_)
{
    int more;
    size_t more_size = sizeof (more);
    do {
        zmq_msg_t recv_part, sent_part;
        TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init (&recv_part));

        TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_recv (&recv_part, socket_, 0));

        TEST_ASSERT_SUCCESS_ERRNO (
          zmq_getsockopt (socket_, ZMQ_RCVMORE, &more, &more_size));

        zmq_msg_init (&sent_part);
        zmq_msg_copy (&sent_part, &recv_part);

        TEST_ASSERT_SUCCESS_ERRNO (
          zmq_msg_send (&sent_part, socket_, more ? ZMQ_SNDMORE : 0));

        zmq_msg_close (&recv_part);
    } while (more);
}

static int get_events (void *socket_)
{
    int events;
    size_t events_size = sizeof (events);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (socket_, ZMQ_EVENTS, &events, &events_size));
    return events;
}

void test_case_1 ()
{
    //  Case 1: Second send() before a reply arrives in a pipe.

    int events = get_events (req);
    TEST_ASSERT_EQUAL_INT (ZMQ_POLLOUT, events);

    //  Send a request, ensure it arrives, don't send a reply
    s_send_seq (req, "A", "B", SEQ_END);
    s_recv_seq (rep[0], "A", "B", SEQ_END);

    events = get_events (req);
    TEST_ASSERT_EQUAL_INT (ZMQ_POLLOUT, events);

    //  Send another request on the REQ socket
    s_send_seq (req, "C", "D", SEQ_END);
    s_recv_seq (rep[1], "C", "D", SEQ_END);

    events = get_events (req);
    TEST_ASSERT_EQUAL_INT (ZMQ_POLLOUT, events);

    //  Send a reply to the first request - that should be discarded by the REQ
    s_send_seq (rep[0], "WRONG", SEQ_END);

    //  Send the expected reply
    s_send_seq (rep[1], "OK", SEQ_END);
    s_recv_seq (req, "OK", SEQ_END);

    //  Another standard req-rep cycle, just to check
    s_send_seq (req, "E", SEQ_END);
    s_recv_seq (rep[2], "E", SEQ_END);
    s_send_seq (rep[2], "F", "G", SEQ_END);
    s_recv_seq (req, "F", "G", SEQ_END);
}

void test_case_2 ()
{
    //  Case 2: Second send() after a reply is already in a pipe on the REQ.

    // TODO instead of rerunning the previous test cases, only do the relevant parts (or change the peer)
    test_case_1 ();

    //  Send a request, ensure it arrives, send a reply
    s_send_seq (req, "H", SEQ_END);
    s_recv_seq (rep[3], "H", SEQ_END);
    s_send_seq (rep[3], "BAD", SEQ_END);

    //  Wait for message to be there.
    msleep (SETTLE_TIME);

    //  Without receiving that reply, send another request on the REQ socket
    s_send_seq (req, "I", SEQ_END);
    s_recv_seq (rep[4], "I", SEQ_END);

    //  Send the expected reply
    s_send_seq (rep[4], "GOOD", SEQ_END);
    s_recv_seq (req, "GOOD", SEQ_END);
}

void test_case_3 ()
{
    //  Case 3: Check issue #1690. Two send() in a row should not close the
    //  communication pipes. For example pipe from req to rep[0] should not be
    //  closed after executing Case 1. So rep[0] should be the next to receive,
    //  not rep[1].

    // TODO instead of rerunning the previous test cases, only do the relevant parts (or change the peer)
    test_case_2 ();

    s_send_seq (req, "J", SEQ_END);
    s_recv_seq (rep[0], "J", SEQ_END);
}

void test_case_4 ()
{
    // TODO this test case does not use the sockets from setUp

    //  Case 4: Check issue #1695. As messages may pile up before a responder
    //  is available, we check that responses to messages other than the last
    //  sent one are correctly discarded by the REQ pipe

    //  Setup REQ socket as client
    void *req = test_context_socket (ZMQ_REQ);

    int enabled = 1;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (req, ZMQ_REQ_RELAXED, &enabled, sizeof (int)));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (req, ZMQ_REQ_CORRELATE, &enabled, sizeof (int)));

    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (req, ENDPOINT_0));

    //  Setup ROUTER socket as server but do not bind it just yet
    void *router = test_context_socket (ZMQ_ROUTER);

    //  Send two requests
    s_send_seq (req, "TO_BE_DISCARDED", SEQ_END);
    s_send_seq (req, "TO_BE_ANSWERED", SEQ_END);

    //  Bind server allowing it to receive messages
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (router, ENDPOINT_0));

    //  Read the two messages and send them back as is
    bounce (router);
    bounce (router);

    //  Read the expected correlated reply. As the ZMQ_REQ_CORRELATE is active,
    //  the expected answer is "TO_BE_ANSWERED", not "TO_BE_DISCARDED".
    s_recv_seq (req, "TO_BE_ANSWERED", SEQ_END);

    test_context_socket_close_zero_linger (req);
    test_context_socket_close_zero_linger (router);
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_case_1);
    RUN_TEST (test_case_2);
    RUN_TEST (test_case_3);
    RUN_TEST (test_case_4);
    return UNITY_END ();
}
