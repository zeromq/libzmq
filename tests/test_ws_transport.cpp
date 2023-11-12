/* SPDX-License-Identifier: MPL-2.0 */

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
    snprintf (connect_address, MAX_SOCKET_STRING * sizeof (char),
              "ws://127.0.0.1%s", strrchr (bind_address, ':'));

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

void test_pub_sub ()
{
    char connect_address[MAX_SOCKET_STRING];
    size_t addr_length = sizeof (connect_address);
    void *sb = test_context_socket (ZMQ_XPUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (sb, "ws://127.0.0.1:*"));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (sb, ZMQ_LAST_ENDPOINT, connect_address, &addr_length));

    void *sc = test_context_socket (ZMQ_SUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (sc, ZMQ_SUBSCRIBE, "A", 1));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (sc, ZMQ_SUBSCRIBE, "B", 1));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc, connect_address));

    recv_string_expect_success (sb, "\1A", 0);
    recv_string_expect_success (sb, "\1B", 0);

    send_string_expect_success (sb, "A", 0);
    send_string_expect_success (sb, "B", 0);

    recv_string_expect_success (sc, "A", 0);
    recv_string_expect_success (sc, "B", 0);

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
    RUN_TEST (test_pub_sub);

    if (zmq_has ("curve"))
        RUN_TEST (test_curve);

    return UNITY_END ();
}
