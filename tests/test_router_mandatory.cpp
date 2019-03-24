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

#ifdef ZMQ_BUILD_DRAFT_API
bool send_msg_to_peer_if_ready (void *router_, const char *peer_routing_id_)
{
    int rc = TEST_ASSERT_SUCCESS_MESSAGE_ERRNO (
      zmq_socket_get_peer_state (router_, peer_routing_id_, 1),
      peer_routing_id_);
    if (rc & ZMQ_POLLOUT) {
        send_string_expect_success (router_, peer_routing_id_,
                                    ZMQ_SNDMORE | ZMQ_DONTWAIT);
        send_string_expect_success (router_, "Hello", ZMQ_DONTWAIT);

        return true;
    }
    return false;
}
#endif

void test_get_peer_state ()
{
#ifdef ZMQ_BUILD_DRAFT_API
    void *router = test_context_socket (ZMQ_ROUTER);

    int mandatory = 1;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (router, ZMQ_ROUTER_MANDATORY,
                                               &mandatory, sizeof (mandatory)));

    const char *my_endpoint = "inproc://test_get_peer_state";
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (router, my_endpoint));

    void *dealer1 = test_context_socket (ZMQ_DEALER);
    void *dealer2 = test_context_socket (ZMQ_DEALER);

    //  Lower HWMs to allow doing the test with fewer messages
    const int hwm = 100;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (router, ZMQ_SNDHWM, &hwm, sizeof (int)));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (dealer1, ZMQ_RCVHWM, &hwm, sizeof (int)));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (dealer2, ZMQ_RCVHWM, &hwm, sizeof (int)));

    const char *dealer1_routing_id = "X";
    const char *dealer2_routing_id = "Y";

    //  Name dealer1 "X" and connect it to our router
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (dealer1, ZMQ_ROUTING_ID, dealer1_routing_id, 1));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (dealer1, my_endpoint));

    //  Name dealer2 "Y" and connect it to our router
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (dealer2, ZMQ_ROUTING_ID, dealer2_routing_id, 1));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (dealer2, my_endpoint));

    //  Get message from both dealers to know when connection is ready
    send_string_expect_success (dealer1, "Hello", 0);
    recv_string_expect_success (router, dealer1_routing_id, 0);
    recv_string_expect_success (router, "Hello", 0);

    send_string_expect_success (dealer2, "Hello", 0);
    recv_string_expect_success (router, dealer2_routing_id, 0);
    recv_string_expect_success (router, "Hello", 0);

    void *poller = zmq_poller_new ();
    TEST_ASSERT_NOT_NULL (poller);

    //  Poll on router and dealer1, but not on dealer2
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_poller_add (poller, router, NULL, ZMQ_POLLOUT));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_poller_add (poller, dealer1, NULL, ZMQ_POLLIN));

    const unsigned int count = 10000;
    const unsigned int event_size = 2;
    bool dealer2_blocked = false;
    unsigned int dealer1_sent = 0, dealer2_sent = 0, dealer1_received = 0;
    zmq_poller_event_t events[event_size];
    for (unsigned int iteration = 0; iteration < count; ++iteration) {
        TEST_ASSERT_SUCCESS_ERRNO (
          zmq_poller_wait_all (poller, events, event_size, -1));
        for (unsigned int event_no = 0; event_no < event_size; ++event_no) {
            const zmq_poller_event_t &current_event = events[event_no];
            if (current_event.socket == router
                && current_event.events & ZMQ_POLLOUT) {
                if (send_msg_to_peer_if_ready (router, dealer1_routing_id))
                    ++dealer1_sent;

                if (send_msg_to_peer_if_ready (router, dealer2_routing_id))
                    ++dealer2_sent;
                else
                    dealer2_blocked = true;
            }
            if (current_event.socket == dealer1
                && current_event.events & ZMQ_POLLIN) {
                recv_string_expect_success (dealer1, "Hello", ZMQ_DONTWAIT);
                int more;
                size_t more_size = sizeof (more);
                TEST_ASSERT_SUCCESS_ERRNO (
                  zmq_getsockopt (dealer1, ZMQ_RCVMORE, &more, &more_size));
                TEST_ASSERT_FALSE (more);

                ++dealer1_received;
            }
            // never read from dealer2, so its pipe becomes full eventually
        }
    }
    printf ("dealer1_sent = %u, dealer2_sent = %u, dealer1_received = %u\n",
            dealer1_sent, dealer2_sent, dealer1_received);
    TEST_ASSERT_TRUE (dealer2_blocked);
    zmq_poller_destroy (&poller);

    test_context_socket_close (router);
    test_context_socket_close (dealer1);
    test_context_socket_close (dealer2);
#endif
}

void test_get_peer_state_corner_cases ()
{
#ifdef ZMQ_BUILD_DRAFT_API
    const char peer_routing_id[] = "foo";

    //  call get_peer_state with NULL socket
    int rc = zmq_socket_get_peer_state (NULL, peer_routing_id,
                                        strlen (peer_routing_id));
    TEST_ASSERT_EQUAL_INT (-1, rc);
    TEST_ASSERT_EQUAL_INT (ENOTSOCK, errno);

    void *dealer = test_context_socket (ZMQ_DEALER);
    void *router = test_context_socket (ZMQ_ROUTER);

    //  call get_peer_state with a non-ROUTER socket
    rc = zmq_socket_get_peer_state (dealer, peer_routing_id,
                                    strlen (peer_routing_id));
    TEST_ASSERT_EQUAL_INT (-1, rc);
    TEST_ASSERT_EQUAL_INT (ENOTSUP, errno);

    //  call get_peer_state for an unknown routing id
    rc = zmq_socket_get_peer_state (router, peer_routing_id,
                                    strlen (peer_routing_id));
    TEST_ASSERT_EQUAL_INT (-1, rc);
    TEST_ASSERT_EQUAL_INT (EHOSTUNREACH, errno);

    test_context_socket_close (router);
    test_context_socket_close (dealer);
#endif
}

void test_basic ()
{
    char my_endpoint[MAX_SOCKET_STRING];
    void *router = test_context_socket (ZMQ_ROUTER);
    bind_loopback_ipv4 (router, my_endpoint, sizeof my_endpoint);

    //  Send a message to an unknown peer with the default setting
    //  This will not report any error
    send_string_expect_success (router, "UNKNOWN", ZMQ_SNDMORE);
    send_string_expect_success (router, "DATA", 0);

    //  Send a message to an unknown peer with mandatory routing
    //  This will fail
    int mandatory = 1;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (router, ZMQ_ROUTER_MANDATORY,
                                               &mandatory, sizeof (mandatory)));
    int rc = zmq_send (router, "UNKNOWN", 7, ZMQ_SNDMORE);
    TEST_ASSERT_EQUAL_INT (-1, rc);
    TEST_ASSERT_EQUAL_INT (EHOSTUNREACH, errno);

    //  Create dealer called "X" and connect it to our router
    void *dealer = test_context_socket (ZMQ_DEALER);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (dealer, ZMQ_ROUTING_ID, "X", 1));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (dealer, my_endpoint));

    //  Get message from dealer to know when connection is ready
    send_string_expect_success (dealer, "Hello", 0);
    recv_string_expect_success (router, "X", 0);

    //  Send a message to connected dealer now
    //  It should work
    send_string_expect_success (router, "X", ZMQ_SNDMORE);
    send_string_expect_success (router, "Hello", 0);

    test_context_socket_close (router);
    test_context_socket_close (dealer);
}

int main (void)
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_basic);
    RUN_TEST (test_get_peer_state);
    RUN_TEST (test_get_peer_state_corner_cases);

    return UNITY_END ();
}
