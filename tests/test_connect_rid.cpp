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

const char *rconn1routing_id = "conn1";
const char *x_routing_id = "X";
const char *y_routing_id = "Y";
const char *z_routing_id = "Z";

void test_stream_2_stream ()
{
    char buff[256];
    const char msg[] = "hi 1";
    const int disabled = 0;
    const int zero = 0;
    char my_endpoint[MAX_SOCKET_STRING];

    //  Set up listener STREAM.
    void *rbind = test_context_socket (ZMQ_STREAM);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (rbind, ZMQ_STREAM_NOTIFY, &disabled, sizeof (disabled)));

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (rbind, ZMQ_LINGER, &zero, sizeof zero));
    bind_loopback_ipv4 (rbind, my_endpoint, sizeof my_endpoint);

    //  Set up connection stream.
    void *rconn1 = test_context_socket (ZMQ_STREAM);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (rconn1, ZMQ_LINGER, &zero, sizeof zero));

    //  Do the connection.
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (rconn1, ZMQ_CONNECT_ROUTING_ID,
                                               rconn1routing_id,
                                               strlen (rconn1routing_id)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (rconn1, my_endpoint));

    /*  Uncomment to test assert on duplicate routing id.
    //  Test duplicate connect attempt.
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (rconn1, ZMQ_CONNECT_ROUTING_ID, rconn1routing_id, strlen(rconn1routing_id)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (rconn1, bindip));
*/
    //  Send data to the bound stream.
    send_string_expect_success (rconn1, rconn1routing_id, ZMQ_SNDMORE);
    send_string_expect_success (rconn1, msg, 0);

    //  Accept data on the bound stream.
    TEST_ASSERT_GREATER_THAN (
      0, TEST_ASSERT_SUCCESS_ERRNO (zmq_recv (rbind, buff, 256, 0)));
    TEST_ASSERT_EQUAL (0, buff[0]); // an auto-generated routing id
    recv_string_expect_success (rbind, msg, 0);

    // Handle close of the socket.
    TEST_ASSERT_SUCCESS_ERRNO (zmq_unbind (rbind, my_endpoint));
    test_context_socket_close (rbind);
    test_context_socket_close (rconn1);
}

void test_router_2_router (bool named_)
{
    char buff[256];
    const char msg[] = "hi 1";
    const int zero = 0;
    char my_endpoint[MAX_SOCKET_STRING];

    //  Create bind socket.
    void *rbind = test_context_socket (ZMQ_ROUTER);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (rbind, ZMQ_LINGER, &zero, sizeof (zero)));
    bind_loopback_ipv4 (rbind, my_endpoint, sizeof my_endpoint);

    //  Create connection socket.
    void *rconn1 = test_context_socket (ZMQ_ROUTER);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (rconn1, ZMQ_LINGER, &zero, sizeof (zero)));

    //  If we're in named mode, set some identities.
    if (named_) {
        TEST_ASSERT_SUCCESS_ERRNO (
          zmq_setsockopt (rbind, ZMQ_ROUTING_ID, x_routing_id, 1));
        TEST_ASSERT_SUCCESS_ERRNO (
          zmq_setsockopt (rconn1, ZMQ_ROUTING_ID, y_routing_id, 1));
    }

    //  Make call to connect using a connect_routing_id.
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (rconn1, ZMQ_CONNECT_ROUTING_ID,
                                               rconn1routing_id,
                                               strlen (rconn1routing_id)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (rconn1, my_endpoint));
    /*  Uncomment to test assert on duplicate routing id
    //  Test duplicate connect attempt.
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (rconn1, ZMQ_CONNECT_ROUTING_ID, rconn1routing_id, strlen (rconn1routing_id)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (rconn1, bindip));
*/
    //  Send some data.

    send_string_expect_success (rconn1, rconn1routing_id, ZMQ_SNDMORE);
    send_string_expect_success (rconn1, msg, 0);

    //  Receive the name.
    const int routing_id_len = zmq_recv (rbind, buff, 256, 0);
    if (named_) {
        TEST_ASSERT_EQUAL_INT (strlen (y_routing_id), routing_id_len);
        TEST_ASSERT_EQUAL_STRING_LEN (y_routing_id, buff, routing_id_len);
    } else {
        TEST_ASSERT_TRUE (routing_id_len && 0 == buff[0]);
    }

    //  Receive the data.
    recv_string_expect_success (rbind, msg, 0);

    //  Send some data back.
    const int ret = zmq_send (rbind, buff, routing_id_len, ZMQ_SNDMORE);
    TEST_ASSERT_EQUAL_INT (routing_id_len, ret);
    send_string_expect_success (rbind, "ok", 0);

    //  If bound socket identity naming a problem, we'll likely see something funky here.
    recv_string_expect_success (rconn1, rconn1routing_id, 0);
    recv_string_expect_success (rconn1, "ok", 0);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_unbind (rbind, my_endpoint));
    test_context_socket_close (rbind);
    test_context_socket_close (rconn1);
}

void test_router_2_router_while_receiving ()
{
    char buff[256];
    const char msg[] = "hi 1";
    const int zero = 0;
    char x_endpoint[MAX_SOCKET_STRING];
    char z_endpoint[MAX_SOCKET_STRING];

    //  Create xbind socket.
    void *xbind = test_context_socket (ZMQ_ROUTER);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (xbind, ZMQ_LINGER, &zero, sizeof (zero)));
    bind_loopback_ipv4 (xbind, x_endpoint, sizeof x_endpoint);

    //  Create zbind socket.
    void *zbind = test_context_socket (ZMQ_ROUTER);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (zbind, ZMQ_LINGER, &zero, sizeof (zero)));
    bind_loopback_ipv4 (zbind, z_endpoint, sizeof z_endpoint);

    //  Create connection socket.
    void *yconn = test_context_socket (ZMQ_ROUTER);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (yconn, ZMQ_LINGER, &zero, sizeof (zero)));

    // set identities for each socket
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      xbind, ZMQ_ROUTING_ID, x_routing_id, strlen (x_routing_id)));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (yconn, ZMQ_ROUTING_ID, y_routing_id, 2));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      zbind, ZMQ_ROUTING_ID, z_routing_id, strlen (z_routing_id)));

    //  Connect Y to X using a routing id
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      yconn, ZMQ_CONNECT_ROUTING_ID, x_routing_id, strlen (x_routing_id)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (yconn, x_endpoint));

    //  Send some data from Y to X.
    send_string_expect_success (yconn, x_routing_id, ZMQ_SNDMORE);
    send_string_expect_success (yconn, msg, 0);

    // wait for the Y->X message to be received
    msleep (SETTLE_TIME);

    // Now X tries to connect to Z and send a message
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      xbind, ZMQ_CONNECT_ROUTING_ID, z_routing_id, strlen (z_routing_id)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (xbind, z_endpoint));

    //  Try to send some data from X to Z.
    send_string_expect_success (xbind, z_routing_id, ZMQ_SNDMORE);
    send_string_expect_success (xbind, msg, 0);

    // wait for the X->Z message to be received (so that our non-blocking check will actually
    // fail if the message is routed to Y)
    msleep (SETTLE_TIME);

    // nothing should have been received on the Y socket
    TEST_ASSERT_FAILURE_ERRNO (EAGAIN,
                               zmq_recv (yconn, buff, 256, ZMQ_DONTWAIT));

    // the message should have been received on the Z socket
    recv_string_expect_success (zbind, x_routing_id, 0);
    recv_string_expect_success (zbind, msg, 0);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_unbind (xbind, x_endpoint));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_unbind (zbind, z_endpoint));

    test_context_socket_close (yconn);
    test_context_socket_close (xbind);
    test_context_socket_close (zbind);
}

void test_router_2_router_unnamed ()
{
    test_router_2_router (false);
}

void test_router_2_router_named ()
{
    test_router_2_router (true);
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_stream_2_stream);
    RUN_TEST (test_router_2_router_unnamed);
    RUN_TEST (test_router_2_router_named);
    RUN_TEST (test_router_2_router_while_receiving);
    return UNITY_END ();
}
