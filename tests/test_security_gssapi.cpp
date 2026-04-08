/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_monitoring.hpp"
#include "testutil_unity.hpp"

#include <stdlib.h>
#include <string.h>

//  This test requires a KRB5 environment with the following
//  service principal (substitute your host.domain and REALM):
//
//    zmqtest2/host.domain@REALM   (host.domain should be host running test)
//
//  Export keys for this principal to a keytab file and set the environment
//  variables KRB5_KTNAME and KRB5_CLIENT_KTNAME to FILE:/path/to/your/keytab.
//  The test will use it both for client and server roles.
//
//  The test is derived in large part from test_security_curve.cpp

const char *name = "zmqtest2";

static volatile int zap_deny_all = 0;

//  --------------------------------------------------------------------------
//  This methods receives and validates ZAP requests (allowing or denying
//  each client connection).
//  N.B. on failure, each crypto type in keytab will be tried

static void zap_handler (void *handler_)
{
    //  Process ZAP requests forever
    while (true) {
        char *version = s_recv (handler_);
        if (!version)
            break; //  Terminating

        char *sequence = s_recv (handler_);
        char *domain = s_recv (handler_);
        char *address = s_recv (handler_);
        char *routing_id = s_recv (handler_);
        char *mechanism = s_recv (handler_);
        char *principal = s_recv (handler_);

        TEST_ASSERT_EQUAL_STRING ("1.0", version);
        TEST_ASSERT_EQUAL_STRING ("GSSAPI", mechanism);

        send_string_expect_success (handler_, version, ZMQ_SNDMORE);
        send_string_expect_success (handler_, sequence, ZMQ_SNDMORE);

        if (!zap_deny_all) {
            send_string_expect_success (handler_, "200", ZMQ_SNDMORE);
            send_string_expect_success (handler_, "OK", ZMQ_SNDMORE);
            send_string_expect_success (handler_, "anonymous", ZMQ_SNDMORE);
            send_string_expect_success (handler_, "", 0);
            //fprintf (stderr, "ALLOW %s\n", principal);
        } else {
            send_string_expect_success (handler_, "400", ZMQ_SNDMORE);
            send_string_expect_success (handler_, "Denied", ZMQ_SNDMORE);
            send_string_expect_success (handler_, "", ZMQ_SNDMORE);
            send_string_expect_success (handler_, "", 0);
            //fprintf (stderr, "DENY %s\n", principal);
        }
        free (version);
        free (sequence);
        free (domain);
        free (address);
        free (routing_id);
        free (mechanism);
        free (principal);
    }
    zmq_close (handler_);
}

static char my_endpoint[MAX_SOCKET_STRING];
static void *zap_thread;
static void *server;
static void *server_mon;

void check_krb_available ()
{
    if (!getenv ("KRB5_KTNAME") || !getenv ("KRB5_CLIENT_KTNAME")) {
        TEST_IGNORE_MESSAGE ("KRB5 environment unavailable, skipping test");
    }
}

void setUp ()
{
    setup_test_context ();

    zap_thread = 0;
    server = NULL;
    server_mon = NULL;

    check_krb_available ();

    //  Spawn ZAP handler
    //  We create and bind ZAP socket in main thread to avoid case
    //  where child thread does not start up fast enough.
    void *handler = zmq_socket (get_test_context (), ZMQ_REP);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (handler, "inproc://zeromq.zap.01"));
    zap_thread = zmq_threadstart (&zap_handler, handler);

    //  Server socket will accept connections
    server = test_context_socket (ZMQ_DEALER);
    int as_server = 1;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (server, ZMQ_GSSAPI_SERVER, &as_server, sizeof (int)));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (server, ZMQ_GSSAPI_PRINCIPAL, name, strlen (name) + 1));
    int name_type = ZMQ_GSSAPI_NT_HOSTBASED;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      server, ZMQ_GSSAPI_PRINCIPAL_NAMETYPE, &name_type, sizeof (name_type)));
    bind_loopback_ipv4 (server, my_endpoint, sizeof my_endpoint);

    //  Monitor handshake events on the server
    TEST_ASSERT_SUCCESS_ERRNO (zmq_socket_monitor (
      server, "inproc://monitor-server",
      ZMQ_EVENT_HANDSHAKE_SUCCEEDED | ZMQ_EVENT_HANDSHAKE_FAILED_AUTH
        | ZMQ_EVENT_HANDSHAKE_FAILED_PROTOCOL));

    //  Create socket for collecting monitor events
    server_mon = test_context_socket (ZMQ_PAIR);

    //  Connect it to the inproc endpoints so they'll get events
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_connect (server_mon, "inproc://monitor-server"));
}

void tearDown ()
{
    //  Shutdown
    if (server_mon)
        test_context_socket_close_zero_linger (server_mon);
    if (server)
        test_context_socket_close (server);
    teardown_test_context ();

    //  Wait until ZAP handler terminates
    if (zap_thread)
        zmq_threadclose (zap_thread);
}

static void setup_gssapi_client_socket (void *client_)
{
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      client_, ZMQ_GSSAPI_SERVICE_PRINCIPAL, name, strlen (name) + 1));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      client_, ZMQ_GSSAPI_PRINCIPAL, name, strlen (name) + 1));
    int name_type = ZMQ_GSSAPI_NT_HOSTBASED;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      client_, ZMQ_GSSAPI_PRINCIPAL_NAMETYPE, &name_type, sizeof (name_type)));
}

//  Test that PUB/SUB subscriptions work correctly with GSSAPI encryption.
//  This is a regression test for the bug where subscribe/cancel flags were
//  lost during GSSAPI encode_message(), causing subscriptions to be silently
//  dropped or corrupted after reconnection.
void test_pubsub_subscription ()
{
    //  Create a PUB socket acting as server
    void *pub = test_context_socket (ZMQ_PUB);
    int as_server = 1;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (pub, ZMQ_GSSAPI_SERVER, &as_server, sizeof (int)));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (pub, ZMQ_GSSAPI_PRINCIPAL, name, strlen (name) + 1));
    int name_type = ZMQ_GSSAPI_NT_HOSTBASED;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      pub, ZMQ_GSSAPI_PRINCIPAL_NAMETYPE, &name_type, sizeof (name_type)));

    char pub_endpoint[MAX_SOCKET_STRING];
    bind_loopback_ipv4 (pub, pub_endpoint, sizeof pub_endpoint);

    //  Create a SUB socket acting as client
    void *sub = test_context_socket (ZMQ_SUB);
    setup_gssapi_client_socket (sub);

    //  Subscribe to topic "test"
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sub, ZMQ_SUBSCRIBE, "test", 4));

    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sub, pub_endpoint));

    //  Give time for connection and subscription to be established
    msleep (500);

    //  Send a matching message
    send_string_expect_success (pub, "test message", 0);

    //  Should receive the message
    int timeout = 1000;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sub, ZMQ_RCVTIMEO, &timeout, sizeof (timeout)));
    recv_string_expect_success (sub, "test message", 0);

    test_context_socket_close (sub);
    test_context_socket_close (pub);
}

//  Test that PUB/SUB subscriptions survive reconnection with GSSAPI encryption.
//  Specifically tests the bug where xhiccuped() re-sends subscriptions through
//  GSSAPI encode_message() and the subscribe flag was lost, causing the
//  subscription to be silently dropped on the PUB side after reconnect.
void test_pubsub_subscription_after_reconnect ()
{
    //  Create a PUB socket acting as server
    void *pub = test_context_socket (ZMQ_PUB);
    int as_server = 1;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (pub, ZMQ_GSSAPI_SERVER, &as_server, sizeof (int)));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (pub, ZMQ_GSSAPI_PRINCIPAL, name, strlen (name) + 1));
    int name_type = ZMQ_GSSAPI_NT_HOSTBASED;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      pub, ZMQ_GSSAPI_PRINCIPAL_NAMETYPE, &name_type, sizeof (name_type)));

    char pub_endpoint[MAX_SOCKET_STRING];
    bind_loopback_ipv4 (pub, pub_endpoint, sizeof pub_endpoint);

    //  Create a SUB socket, subscribe, and connect
    void *sub = test_context_socket (ZMQ_SUB);
    setup_gssapi_client_socket (sub);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sub, ZMQ_SUBSCRIBE, "test", 4));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sub, pub_endpoint));

    //  Give time for connection and subscription to be established
    msleep (500);

    //  Verify initial subscription works
    send_string_expect_success (pub, "test hello", 0);
    int timeout = 1000;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sub, ZMQ_RCVTIMEO, &timeout, sizeof (timeout)));
    recv_string_expect_success (sub, "test hello", 0);

    //  Simulate server restart: close and rebind PUB on same endpoint
    test_context_socket_close (pub);
    msleep (100);

    pub = test_context_socket (ZMQ_PUB);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (pub, ZMQ_GSSAPI_SERVER, &as_server, sizeof (int)));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (pub, ZMQ_GSSAPI_PRINCIPAL, name, strlen (name) + 1));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      pub, ZMQ_GSSAPI_PRINCIPAL_NAMETYPE, &name_type, sizeof (name_type)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (pub, pub_endpoint));

    //  Give time for the SUB to reconnect and re-send subscriptions
    msleep (1000);

    //  Send a matching message - subscription should still be active
    send_string_expect_success (pub, "test world", 0);
    recv_string_expect_success (sub, "test world", 0);

    //  Also verify that a non-matching message is filtered
    send_string_expect_success (pub, "other message", 0);
    char buf[64];
    int rc = zmq_recv (sub, buf, sizeof buf, 0);
    TEST_ASSERT_EQUAL_INT (-1, rc);
    TEST_ASSERT_EQUAL_INT (EAGAIN, errno);

    test_context_socket_close (sub);
    test_context_socket_close (pub);
}

void test_valid_creds ()
{
    void *client = test_context_socket (ZMQ_DEALER);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      client, ZMQ_GSSAPI_SERVICE_PRINCIPAL, name, strlen (name) + 1));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (client, ZMQ_GSSAPI_PRINCIPAL, name, strlen (name) + 1));
    int name_type = ZMQ_GSSAPI_NT_HOSTBASED;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      client, ZMQ_GSSAPI_PRINCIPAL_NAMETYPE, &name_type, sizeof (name_type)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (client, my_endpoint));

    bounce (server, client);
    test_context_socket_close (client);

    int event = get_monitor_event (server_mon, NULL, NULL);
    TEST_ASSERT_EQUAL_INT (ZMQ_EVENT_HANDSHAKE_SUCCEEDED, event);
}

//  Check security with valid but unauthorized credentials
//  Note: ZAP may see multiple requests - after a failure, client will
//  fall back to other crypto types for principal, if available.
void test_unauth_creds ()
{
    void *client = test_context_socket (ZMQ_DEALER);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      client, ZMQ_GSSAPI_SERVICE_PRINCIPAL, name, strlen (name) + 1));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (client, ZMQ_GSSAPI_PRINCIPAL, name, strlen (name) + 1));
    int name_type = ZMQ_GSSAPI_NT_HOSTBASED;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      client, ZMQ_GSSAPI_PRINCIPAL_NAMETYPE, &name_type, sizeof (name_type)));
    zap_deny_all = 1;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (client, my_endpoint));

    expect_bounce_fail (server, client);
    test_context_socket_close_zero_linger (client);

    int event = get_monitor_event (server_mon, NULL, NULL);
    TEST_ASSERT_EQUAL_INT (ZMQ_EVENT_HANDSHAKE_FAILED_AUTH, event);
}

//  Check GSSAPI security with NULL client credentials
//  This must be caught by the gssapi_server class, not passed to ZAP
void test_null_creds ()
{
    void *client = test_context_socket (ZMQ_DEALER);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (client, my_endpoint));
    expect_bounce_fail (server, client);
    test_context_socket_close_zero_linger (client);

    int error = 0;
    int event = get_monitor_event (server_mon, &error, NULL);
    TEST_ASSERT_EQUAL_INT (ZMQ_EVENT_HANDSHAKE_FAILED_PROTOCOL, event);
    TEST_ASSERT_EQUAL_INT (ZMQ_PROTOCOL_ERROR_ZMTP_MECHANISM_MISMATCH, error);
}

//  Check GSSAPI security with PLAIN client credentials
//  This must be caught by the curve_server class, not passed to ZAP
void test_plain_creds ()
{
    void *client = test_context_socket (ZMQ_DEALER);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (client, ZMQ_PLAIN_USERNAME, "admin", 5));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (client, ZMQ_PLAIN_PASSWORD, "password", 8));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (client, my_endpoint));
    expect_bounce_fail (server, client);
    test_context_socket_close_zero_linger (client);
}

// Unauthenticated messages from a vanilla socket shouldn't be received
void test_vanilla_socket ()
{
    fd_t s = connect_socket (my_endpoint);
    // send anonymous ZMTP/1.0 greeting
    send (s, "\x01\x00", 2, 0);
    // send sneaky message that shouldn't be received
    send (s, "\x08\x00sneaky\0", 9, 0);
    int timeout = 250;
    zmq_setsockopt (server, ZMQ_RCVTIMEO, &timeout, sizeof (timeout));
    char *buf = s_recv (server);
    if (buf != NULL) {
        printf ("Received unauthenticated message: %s\n", buf);
        TEST_ASSERT_NULL (buf);
    }
    close (s);
}

int main (void)
{
    // Avoid entanglements with user's credential cache
    setenv ("KRB5CCNAME", "MEMORY", 1);

    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_valid_creds);
    RUN_TEST (test_null_creds);
    RUN_TEST (test_plain_creds);
    RUN_TEST (test_vanilla_socket);
    RUN_TEST (test_unauth_creds);
    RUN_TEST (test_pubsub_subscription);
    RUN_TEST (test_pubsub_subscription_after_reconnect);
    return UNITY_END ();
}
