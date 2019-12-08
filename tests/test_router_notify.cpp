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

void test_sockopt_router_notify ()
{
    void *router = test_context_socket (ZMQ_ROUTER);
    int opt_notify;

    int opt_notify_read;
    size_t opt_notify_read_size = sizeof (opt_notify_read);


    // default value is off when socket is constructed
    TEST_ASSERT_SUCCESS_ERRNO (zmq_getsockopt (
      router, ZMQ_ROUTER_NOTIFY, &opt_notify_read, &opt_notify_read_size));

    TEST_ASSERT_EQUAL (0, opt_notify_read);


    // valid value - Connect
    opt_notify = ZMQ_NOTIFY_CONNECT;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      router, ZMQ_ROUTER_NOTIFY, &opt_notify, sizeof (opt_notify)));

    TEST_ASSERT_SUCCESS_ERRNO (zmq_getsockopt (
      router, ZMQ_ROUTER_NOTIFY, &opt_notify_read, &opt_notify_read_size));

    TEST_ASSERT_EQUAL (opt_notify, opt_notify_read);


    // valid value - Disconnect
    opt_notify = ZMQ_NOTIFY_DISCONNECT;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      router, ZMQ_ROUTER_NOTIFY, &opt_notify, sizeof (opt_notify)));

    TEST_ASSERT_SUCCESS_ERRNO (zmq_getsockopt (
      router, ZMQ_ROUTER_NOTIFY, &opt_notify_read, &opt_notify_read_size));

    TEST_ASSERT_EQUAL (opt_notify, opt_notify_read);


    // valid value - Off
    opt_notify = 0;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      router, ZMQ_ROUTER_NOTIFY, &opt_notify, sizeof (opt_notify)));

    TEST_ASSERT_SUCCESS_ERRNO (zmq_getsockopt (
      router, ZMQ_ROUTER_NOTIFY, &opt_notify_read, &opt_notify_read_size));

    TEST_ASSERT_EQUAL (opt_notify, opt_notify_read);


    // valid value - Both
    opt_notify = ZMQ_NOTIFY_CONNECT | ZMQ_NOTIFY_DISCONNECT;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      router, ZMQ_ROUTER_NOTIFY, &opt_notify, sizeof (opt_notify)));

    TEST_ASSERT_SUCCESS_ERRNO (zmq_getsockopt (
      router, ZMQ_ROUTER_NOTIFY, &opt_notify_read, &opt_notify_read_size));

    TEST_ASSERT_EQUAL (opt_notify, opt_notify_read);


    // value boundary
    opt_notify = -1;
    TEST_ASSERT_FAILURE_ERRNO (
      EINVAL, zmq_setsockopt (router, ZMQ_ROUTER_NOTIFY, &opt_notify,
                              sizeof (opt_notify)));

    opt_notify = (ZMQ_NOTIFY_CONNECT | ZMQ_NOTIFY_DISCONNECT) + 1;
    TEST_ASSERT_FAILURE_ERRNO (
      EINVAL, zmq_setsockopt (router, ZMQ_ROUTER_NOTIFY, &opt_notify,
                              sizeof (opt_notify)));

    // failures don't update the value
    TEST_ASSERT_SUCCESS_ERRNO (zmq_getsockopt (
      router, ZMQ_ROUTER_NOTIFY, &opt_notify_read, &opt_notify_read_size));

    TEST_ASSERT_EQUAL (ZMQ_NOTIFY_CONNECT | ZMQ_NOTIFY_DISCONNECT,
                       opt_notify_read);


    test_context_socket_close (router);


    // check a non-router socket type
    void *dealer = test_context_socket (ZMQ_DEALER);

    // setsockopt fails for non-router sockets
    opt_notify = ZMQ_NOTIFY_CONNECT;
    TEST_ASSERT_FAILURE_ERRNO (
      EINVAL, zmq_setsockopt (dealer, ZMQ_ROUTER_NOTIFY, &opt_notify,
                              sizeof (opt_notify)));

    // getsockopts returns off for any non-router socket
    TEST_ASSERT_SUCCESS_ERRNO (zmq_getsockopt (
      dealer, ZMQ_ROUTER_NOTIFY, &opt_notify_read, &opt_notify_read_size));

    TEST_ASSERT_EQUAL (0, opt_notify_read);


    test_context_socket_close (dealer);
}


void test_router_notify_helper (int opt_notify_)
{
    void *router = test_context_socket (ZMQ_ROUTER);
    int opt_more;
    size_t opt_more_length = sizeof (opt_more);
    int opt_events;
    size_t opt_events_length = sizeof (opt_events);
    char connect_address[MAX_SOCKET_STRING];


    // valid values
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      router, ZMQ_ROUTER_NOTIFY, &opt_notify_, sizeof (opt_notify_)));

    bind_loopback_ipv4 (router, connect_address, sizeof connect_address);

    void *dealer = test_context_socket (ZMQ_DEALER);
    const char *dealer_routing_id = "X";

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (dealer, ZMQ_ROUTING_ID, dealer_routing_id, 1));

    // dealer connects
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (dealer, connect_address));

    // connection notification msg
    if (opt_notify_ & ZMQ_NOTIFY_CONNECT) {
        // routing-id only message of the connect
        recv_string_expect_success (router, dealer_routing_id,
                                    0);             // 1st part: routing-id
        recv_string_expect_success (router, "", 0); // 2nd part: empty
        TEST_ASSERT_SUCCESS_ERRNO (
          zmq_getsockopt (router, ZMQ_RCVMORE, &opt_more, &opt_more_length));
        TEST_ASSERT_EQUAL (0, opt_more);
    }

    // test message from the dealer
    send_string_expect_success (dealer, "Hello", 0);
    recv_string_expect_success (router, dealer_routing_id, 0);
    recv_string_expect_success (router, "Hello", 0);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (router, ZMQ_RCVMORE, &opt_more, &opt_more_length));
    TEST_ASSERT_EQUAL (0, opt_more);

    // dealer disconnects
    TEST_ASSERT_SUCCESS_ERRNO (zmq_disconnect (dealer, connect_address));

    // need one more process_commands() (???)
    msleep (SETTLE_TIME);
    zmq_getsockopt (dealer, ZMQ_EVENTS, &opt_events, &opt_events_length);

    // connection notification msg
    if (opt_notify_ & ZMQ_NOTIFY_DISCONNECT) {
        // routing-id only message of the connect
        recv_string_expect_success (router, dealer_routing_id,
                                    0);             // 1st part: routing-id
        recv_string_expect_success (router, "", 0); // 2nd part: empty
        TEST_ASSERT_SUCCESS_ERRNO (
          zmq_getsockopt (router, ZMQ_RCVMORE, &opt_more, &opt_more_length));
        TEST_ASSERT_EQUAL (0, opt_more);
    }

    test_context_socket_close (dealer);
    test_context_socket_close (router);
}


void test_router_notify_connect ()
{
    test_router_notify_helper (ZMQ_NOTIFY_CONNECT);
}


void test_router_notify_disconnect ()
{
    test_router_notify_helper (ZMQ_NOTIFY_DISCONNECT);
}


void test_router_notify_both ()
{
    test_router_notify_helper (ZMQ_NOTIFY_CONNECT | ZMQ_NOTIFY_DISCONNECT);
}


void test_handshake_fail ()
{
    // setup router socket
    void *router = test_context_socket (ZMQ_ROUTER);
    int opt_timeout = 200;
    int opt_notify = ZMQ_NOTIFY_CONNECT | ZMQ_NOTIFY_DISCONNECT;
    char connect_address[MAX_SOCKET_STRING];

    // valid values
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      router, ZMQ_ROUTER_NOTIFY, &opt_notify, sizeof (opt_notify)));

    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      router, ZMQ_RCVTIMEO, &opt_timeout, sizeof (opt_timeout)));

    bind_loopback_ipv4 (router, connect_address, sizeof connect_address);

    // send something on raw tcp
    void *stream = test_context_socket (ZMQ_STREAM);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (stream, connect_address));

    send_string_expect_success (stream, "not-a-handshake", 0);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_disconnect (stream, connect_address));
    test_context_socket_close (stream);

    // no notification delivered
    char buffer[255];
    TEST_ASSERT_FAILURE_ERRNO (EAGAIN,
                               zmq_recv (router, buffer, sizeof (buffer), 0));

    test_context_socket_close (router);
}


void test_error_during_multipart ()
{
    /*
     * If the disconnect occurs in the middle of the multipart
     * message, the socket should not add the notification at the
     * end of the incomplete message. It must discard the incomplete
     * message, and delivert the notification as a new message.
     */

    char connect_address[MAX_SOCKET_STRING];
    char long_str[128] = {0};
    memset (long_str, '*', sizeof (long_str) - 1);

    // setup router
    void *router = test_context_socket (ZMQ_ROUTER);

    int opt_notify = ZMQ_NOTIFY_DISCONNECT;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      router, ZMQ_ROUTER_NOTIFY, &opt_notify, sizeof (opt_notify)));

    int64_t opt_maxmsgsize = 64; // the handshake fails if this is too small
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      router, ZMQ_MAXMSGSIZE, &opt_maxmsgsize, sizeof (opt_maxmsgsize)));

    bind_loopback_ipv4 (router, connect_address, sizeof connect_address);

    // setup dealer
    void *dealer = test_context_socket (ZMQ_DEALER);
    const char *dealer_routing_id = "X";

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (dealer, ZMQ_ROUTING_ID, dealer_routing_id, 1));

    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (dealer, connect_address));


    // send multipart message, the 2nd part causes a disconnect.
    send_string_expect_success (dealer, "Hello2", ZMQ_SNDMORE);
    send_string_expect_success (dealer, long_str, 0);

    // disconnect notification
    recv_string_expect_success (router, dealer_routing_id, 0);
    recv_string_expect_success (router, "", 0);


    test_context_socket_close (dealer);
    test_context_socket_close (router);
}


int main (void)
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_sockopt_router_notify);
    RUN_TEST (test_router_notify_connect);
    RUN_TEST (test_router_notify_disconnect);
    RUN_TEST (test_router_notify_both);
    RUN_TEST (test_handshake_fail);
    RUN_TEST (test_error_during_multipart);

    return UNITY_END ();
}
