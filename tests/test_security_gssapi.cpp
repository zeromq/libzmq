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
#if defined(ZMQ_HAVE_WINDOWS)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdexcept>
#define close closesocket
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

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
//  This methods receives and validates ZAP requestes (allowing or denying
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

//  Read one event off the monitor socket; return value and address
//  by reference, if not null, and event number by value. Returns -1
//  in case of error.
static int get_monitor_event (void *monitor_, int *value_, char **address_)
{
    //  First frame in message contains event number and value
    zmq_msg_t msg;
    zmq_msg_init (&msg);
    if (zmq_msg_recv (&msg, monitor_, 0) == -1)
        return -1; //  Interruped, presumably
    TEST_ASSERT_TRUE (zmq_msg_more (&msg));

    uint8_t *data = (uint8_t *) zmq_msg_data (&msg);
    uint16_t event = *(uint16_t *) (data);
    if (value_)
        *value_ = *(uint32_t *) (data + 2);
    zmq_msg_close (&msg);

    //  Second frame in message contains event address
    zmq_msg_init (&msg);
    if (zmq_msg_recv (&msg, monitor_, 0) == -1)
        return -1; //  Interruped, presumably
    TEST_ASSERT_FALSE (zmq_msg_more (&msg));

    if (address_) {
        uint8_t *data = (uint8_t *) zmq_msg_data (&msg);
        size_t size = zmq_msg_size (&msg);
        *address_ = (char *) malloc (size + 1);
        memcpy (*address_, data, size);
        *address_[size] = 0;
    }
    zmq_msg_close (&msg);

    return event;
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

    int error;
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
    struct sockaddr_in ip4addr;
    int s;
    unsigned short int port;
    int rc = sscanf (my_endpoint, "tcp://127.0.0.1:%hu", &port);
    TEST_ASSERT_EQUAL_INT (1, rc);
    ip4addr.sin_family = AF_INET;
    ip4addr.sin_port = htons (port);
#if defined(ZMQ_HAVE_WINDOWS) && (_WIN32_WINNT < 0x0600)
    ip4addr.sin_addr.s_addr = inet_addr ("127.0.0.1");
#else
    inet_pton (AF_INET, "127.0.0.1", &ip4addr.sin_addr);
#endif

    s = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
    rc = connect (s, (struct sockaddr *) &ip4addr, sizeof (ip4addr));
    TEST_ASSERT_GREATER_THAN (-1, rc);
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
    return UNITY_END ();
    return 0;
}
