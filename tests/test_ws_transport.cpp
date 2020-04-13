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

#include <string.h>
#include "testutil.hpp"
#include "testutil_unity.hpp"

SETUP_TEARDOWN_TESTCONTEXT

void test_roundtrip ()
{
    char bind_address[MAX_SOCKET_STRING];
    char connect_address[MAX_SOCKET_STRING];
    size_t addr_length = sizeof (connect_address);

    void *sb = test_context_socket (ZMQ_REP);
    void *sc = test_context_socket (ZMQ_REQ);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (sb, "ws://*:*/roundtrip"));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (sb, ZMQ_LAST_ENDPOINT, bind_address, &addr_length));

    // Windows can't connect to 0.0.0.0
    sprintf (connect_address, "ws://127.0.0.1%s", strrchr (bind_address, ':'));

    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc, connect_address));

    bounce (sb, sc);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_disconnect (sc, connect_address));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_unbind (sb, bind_address));

    test_context_socket_close (sc);
    test_context_socket_close (sb);
}

void test_roundtrip_without_path ()
{
    char connect_address[MAX_SOCKET_STRING];
    size_t addr_length = sizeof (connect_address);
    void *sb = test_context_socket (ZMQ_REP);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (sb, "ws://127.0.0.1:*"));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (sb, ZMQ_LAST_ENDPOINT, connect_address, &addr_length));

    void *sc = test_context_socket (ZMQ_REQ);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc, connect_address));

    bounce (sb, sc);

    test_context_socket_close (sc);
    test_context_socket_close (sb);
}


void test_heartbeat ()
{
    char connect_address[MAX_SOCKET_STRING];
    size_t addr_length = sizeof (connect_address);
    void *sb = test_context_socket (ZMQ_REP);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (sb, "ws://127.0.0.1:*/heartbeat"));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (sb, ZMQ_LAST_ENDPOINT, connect_address, &addr_length));

    void *sc = test_context_socket (ZMQ_REQ);

    // Setting heartbeat settings
    int ivl = 10;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sc, ZMQ_HEARTBEAT_IVL, &ivl, sizeof (ivl)));

    // Disable reconnect, to make sure the ping-pong actually work
    ivl = -1;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sc, ZMQ_RECONNECT_IVL, &ivl, sizeof (ivl)));

    // Connect to server
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc, connect_address));

    // Make sure some ping and pong going through
    msleep (100);

    bounce (sb, sc);

    test_context_socket_close (sc);
    test_context_socket_close (sb);
}

void test_short_message ()
{
    char connect_address[MAX_SOCKET_STRING];
    size_t addr_length = sizeof (connect_address);
    void *sb = test_context_socket (ZMQ_REP);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (sb, "ws://127.0.0.1:*/short"));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (sb, ZMQ_LAST_ENDPOINT, connect_address, &addr_length));

    void *sc = test_context_socket (ZMQ_REQ);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc, connect_address));

    zmq_msg_t msg;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init_size (&msg, 255));

    for (unsigned char i = 0; i < 255; ++i)
        ((unsigned char *) zmq_msg_data (&msg))[i] = i;

    int rc = zmq_msg_send (&msg, sc, 0);
    TEST_ASSERT_EQUAL_INT (255, rc);

    rc = zmq_msg_recv (&msg, sb, 0);
    TEST_ASSERT_EQUAL_INT (255, rc);

    for (unsigned char i = 0; i < 255; ++i)
        TEST_ASSERT_EQUAL_INT (i, ((unsigned char *) zmq_msg_data (&msg))[i]);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg));

    test_context_socket_close (sc);
    test_context_socket_close (sb);
}

void test_large_message ()
{
    char connect_address[MAX_SOCKET_STRING];
    size_t addr_length = sizeof (connect_address);
    void *sb = test_context_socket (ZMQ_REP);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (sb, "ws://127.0.0.1:*/large"));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (sb, ZMQ_LAST_ENDPOINT, connect_address, &addr_length));

    void *sc = test_context_socket (ZMQ_REQ);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc, connect_address));

    zmq_msg_t msg;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init_size (&msg, 65536));

    for (int i = 0; i < 65536; ++i)
        ((unsigned char *) zmq_msg_data (&msg))[i] = i % 255;

    int rc = zmq_msg_send (&msg, sc, 0);
    TEST_ASSERT_EQUAL_INT (65536, rc);

    rc = zmq_msg_recv (&msg, sb, 0);
    TEST_ASSERT_EQUAL_INT (65536, rc);

    for (int i = 0; i < 65536; ++i)
        TEST_ASSERT_EQUAL_INT (i % 255,
                               ((unsigned char *) zmq_msg_data (&msg))[i]);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg));

    test_context_socket_close (sc);
    test_context_socket_close (sb);
}

void test_curve ()
{
    char connect_address[MAX_SOCKET_STRING];
    size_t addr_length = sizeof (connect_address);
    char client_public[41];
    char client_secret[41];
    char server_public[41];
    char server_secret[41];

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_curve_keypair (server_public, server_secret));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_curve_keypair (client_public, client_secret));

    void *server = test_context_socket (ZMQ_REP);
    int as_server = 1;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (server, ZMQ_CURVE_SERVER, &as_server, sizeof (int)));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (server, ZMQ_CURVE_SECRETKEY, server_secret, 41));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (server, "ws://127.0.0.1:*/roundtrip"));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_getsockopt (server, ZMQ_LAST_ENDPOINT,
                                               connect_address, &addr_length));

    void *client = test_context_socket (ZMQ_REQ);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (client, ZMQ_CURVE_SERVERKEY, server_public, 41));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (client, ZMQ_CURVE_PUBLICKEY, client_public, 41));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (client, ZMQ_CURVE_SECRETKEY, client_secret, 41));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (client, connect_address));

    bounce (server, client);

    test_context_socket_close (client);
    test_context_socket_close (server);
}


void test_mask_shared_msg ()
{
    char connect_address[MAX_SOCKET_STRING];
    size_t addr_length = sizeof (connect_address);
    void *sb = test_context_socket (ZMQ_DEALER);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (sb, "ws://127.0.0.1:*/mask-shared"));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (sb, ZMQ_LAST_ENDPOINT, connect_address, &addr_length));

    void *sc = test_context_socket (ZMQ_DEALER);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc, connect_address));

    zmq_msg_t msg;
    zmq_msg_init_size (
      &msg, 255); // Message have to be long enough so it won't fit inside msg
    unsigned char *data = (unsigned char *) zmq_msg_data (&msg);
    for (int i = 0; i < 255; i++)
        data[i] = i;

    //  Taking a copy to make the msg shared
    zmq_msg_t copy;
    zmq_msg_init (&copy);
    zmq_msg_copy (&copy, &msg);

    //  Sending the shared msg
    int rc = zmq_msg_send (&msg, sc, 0);
    TEST_ASSERT_EQUAL_INT (255, rc);

    //  Recv the msg and check that it was masked correctly
    rc = zmq_msg_recv (&msg, sb, 0);
    TEST_ASSERT_EQUAL_INT (255, rc);
    data = (unsigned char *) zmq_msg_data (&msg);
    for (int i = 0; i < 255; i++)
        TEST_ASSERT_EQUAL_INT (i, data[i]);

    //  Testing that copy was not masked
    data = (unsigned char *) zmq_msg_data (&copy);
    for (int i = 0; i < 255; i++)
        TEST_ASSERT_EQUAL_INT (i, data[i]);

    //  Constant msg cannot be masked as well, as it is constant
    rc = zmq_send_const (sc, "HELLO", 5, 0);
    TEST_ASSERT_EQUAL_INT (5, rc);
    recv_string_expect_success (sb, "HELLO", 0);

    zmq_msg_close (&copy);
    zmq_msg_close (&msg);

    test_context_socket_close (sc);
    test_context_socket_close (sb);
}


int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_roundtrip_without_path);
    RUN_TEST (test_roundtrip);
    RUN_TEST (test_short_message);
    RUN_TEST (test_large_message);
    RUN_TEST (test_heartbeat);
    RUN_TEST (test_mask_shared_msg);

    if (zmq_has ("curve"))
        RUN_TEST (test_curve);

    return UNITY_END ();
}
