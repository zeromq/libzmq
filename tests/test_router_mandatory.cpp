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

#ifdef ZMQ_BUILD_DRAFT_API
bool send_msg_to_peer_if_ready (void *router, const char *peer_routing_id)
{
    int rc = zmq_socket_get_peer_state (router, peer_routing_id, 1);
    if (rc == -1)
        printf ("zmq_socket_get_peer_state failed for %s: %i\n", peer_routing_id,
                errno);
    assert (rc != -1);
    if (rc & ZMQ_POLLOUT) {
        rc = zmq_send (router, peer_routing_id, 1, ZMQ_SNDMORE | ZMQ_DONTWAIT);
        assert (rc == 1);
        rc = zmq_send (router, "Hello", 5, ZMQ_DONTWAIT);
        assert (rc == 5);

        return true;
    }
    return false;
}
#endif

void test_get_peer_state ()
{
#ifdef ZMQ_BUILD_DRAFT_API
    void *ctx = zmq_ctx_new ();
    assert (ctx);
    void *router = zmq_socket (ctx, ZMQ_ROUTER);
    assert (router);

    int rc;
    int mandatory = 1;
    rc = zmq_setsockopt (router, ZMQ_ROUTER_MANDATORY, &mandatory,
                         sizeof (mandatory));

    const char *my_endpoint = "inproc://test_get_peer_state";
    rc = zmq_bind (router, my_endpoint);
    assert (rc == 0);

    void *dealer1 = zmq_socket (ctx, ZMQ_DEALER);
    assert (dealer1);

    void *dealer2 = zmq_socket (ctx, ZMQ_DEALER);
    assert (dealer2);

    //  Lower HWMs to allow doing the test with fewer messages
    int hwm = 100;
    rc = zmq_setsockopt (router, ZMQ_SNDHWM, &hwm, sizeof (int));
    assert (rc == 0);
    rc = zmq_setsockopt (dealer1, ZMQ_RCVHWM, &hwm, sizeof (int));
    assert (rc == 0);
    rc = zmq_setsockopt (dealer2, ZMQ_RCVHWM, &hwm, sizeof (int));
    assert (rc == 0);

    const char *dealer1_routing_id = "X";
    const char *dealer2_routing_id = "Y";

    //  Name dealer1 "X" and connect it to our router
    rc = zmq_setsockopt (dealer1, ZMQ_ROUTING_ID, dealer1_routing_id, 1);
    assert (rc == 0);
    rc = zmq_connect (dealer1, my_endpoint);
    assert (rc == 0);

    //  Name dealer2 "Y" and connect it to our router
    rc = zmq_setsockopt (dealer2, ZMQ_ROUTING_ID, dealer2_routing_id, 1);
    assert (rc == 0);
    rc = zmq_connect (dealer2, my_endpoint);
    assert (rc == 0);

    //  Get message from both dealers to know when connection is ready
    char buffer[255];
    rc = zmq_send (dealer1, "Hello", 5, 0);
    assert (rc == 5);
    rc = zmq_recv (router, buffer, 255, 0);
    assert (rc == 1);
    assert (0 == memcmp (buffer, dealer1_routing_id, rc));
    rc = zmq_recv (router, buffer, 255, 0);
    assert (rc == 5);

    rc = zmq_send (dealer2, "Hello", 5, 0);
    assert (rc == 5);
    rc = zmq_recv (router, buffer, 255, 0);
    assert (rc == 1);
    assert (0 == memcmp (buffer, dealer2_routing_id, rc));
    rc = zmq_recv (router, buffer, 255, 0);
    assert (rc == 5);

    void *poller = zmq_poller_new ();
    assert (poller);

    //  Poll on router and dealer1, but not on dealer2
    rc = zmq_poller_add (poller, router, NULL, ZMQ_POLLOUT);
    assert (rc == 0);
    rc = zmq_poller_add (poller, dealer1, NULL, ZMQ_POLLIN);
    assert (rc == 0);

    const unsigned int count = 10000;
    const unsigned int event_size = 2;
    bool dealer2_blocked = false;
    unsigned int dealer1_sent = 0, dealer2_sent = 0, dealer1_received = 0;
    zmq_poller_event_t events[event_size];
    for (unsigned int iteration = 0; iteration < count; ++iteration) {
        rc = zmq_poller_wait_all (poller, events, event_size, -1);
        assert (rc != -1);
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
                rc = zmq_recv (dealer1, buffer, 255, ZMQ_DONTWAIT);
                assert (rc == 5);
                int more;
                size_t more_size = sizeof (more);
                rc = zmq_getsockopt (dealer1, ZMQ_RCVMORE, &more, &more_size);
                assert (rc == 0);
                assert (!more);

                ++dealer1_received;
            }
            // never read from dealer2, so its pipe becomes full eventually
        }
    }
    printf ("dealer1_sent = %u, dealer2_sent = %u, dealer1_received = %u\n",
            dealer1_sent, dealer2_sent, dealer1_received);
    assert (dealer2_blocked);
    zmq_poller_destroy (&poller);

    rc = zmq_close (router);
    assert (rc == 0);

    rc = zmq_close (dealer1);
    assert (rc == 0);

    rc = zmq_close (dealer2);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);
#endif
}

void test_get_peer_state_corner_cases ()
{
#ifdef ZMQ_BUILD_DRAFT_API
    const char peer_routing_id[] = "foo";

    //  call get_peer_state with NULL socket
    int rc =
      zmq_socket_get_peer_state (NULL, peer_routing_id, strlen (peer_routing_id));
    assert (rc == -1 && errno == ENOTSOCK);

    void *ctx = zmq_ctx_new ();
    assert (ctx);
    void *dealer = zmq_socket (ctx, ZMQ_DEALER);
    assert (dealer);
    void *router = zmq_socket (ctx, ZMQ_ROUTER);
    assert (router);

    //  call get_peer_state with a non-ROUTER socket
    rc =
      zmq_socket_get_peer_state (dealer, peer_routing_id, strlen (peer_routing_id));
    assert (rc == -1 && errno == ENOTSUP);

    //  call get_peer_state for an unknown routing id
    rc =
      zmq_socket_get_peer_state (router, peer_routing_id, strlen (peer_routing_id));
    assert (rc == -1 && errno == EHOSTUNREACH);

    rc = zmq_close (router);
    assert (rc == 0);

    rc = zmq_close (dealer);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

#endif
}

void test_basic ()
{
    size_t len = MAX_SOCKET_STRING;
    char my_endpoint[MAX_SOCKET_STRING];
    void *ctx = zmq_ctx_new ();
    assert (ctx);
    void *router = zmq_socket (ctx, ZMQ_ROUTER);
    assert (router);

    int rc = zmq_bind (router, "tcp://127.0.0.1:*");
    assert (rc == 0);

    rc = zmq_getsockopt (router, ZMQ_LAST_ENDPOINT, my_endpoint, &len);
    assert (rc == 0);

    //  Send a message to an unknown peer with the default setting
    //  This will not report any error
    rc = zmq_send (router, "UNKNOWN", 7, ZMQ_SNDMORE);
    assert (rc == 7);
    rc = zmq_send (router, "DATA", 4, 0);
    assert (rc == 4);

    //  Send a message to an unknown peer with mandatory routing
    //  This will fail
    int mandatory = 1;
    rc = zmq_setsockopt (router, ZMQ_ROUTER_MANDATORY, &mandatory,
                         sizeof (mandatory));
    assert (rc == 0);
    rc = zmq_send (router, "UNKNOWN", 7, ZMQ_SNDMORE);
    assert (rc == -1 && errno == EHOSTUNREACH);

    //  Create dealer called "X" and connect it to our router
    void *dealer = zmq_socket (ctx, ZMQ_DEALER);
    assert (dealer);
    rc = zmq_setsockopt (dealer, ZMQ_ROUTING_ID, "X", 1);
    assert (rc == 0);
    rc = zmq_connect (dealer, my_endpoint);
    assert (rc == 0);

    //  Get message from dealer to know when connection is ready
    char buffer[255];
    rc = zmq_send (dealer, "Hello", 5, 0);
    assert (rc == 5);
    rc = zmq_recv (router, buffer, 255, 0);
    assert (rc == 1);
    assert (buffer[0] == 'X');

    //  Send a message to connected dealer now
    //  It should work
    rc = zmq_send (router, "X", 1, ZMQ_SNDMORE);
    assert (rc == 1);
    rc = zmq_send (router, "Hello", 5, 0);
    assert (rc == 5);

    rc = zmq_close (router);
    assert (rc == 0);

    rc = zmq_close (dealer);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);
}

int main (void)
{
    setup_test_environment ();

    test_basic ();
    test_get_peer_state ();
    test_get_peer_state_corner_cases ();

    return 0;
}
