/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_monitoring.hpp"
#include "testutil_unity.hpp"

#include <stdlib.h>
#include <string.h>

static void zap_handler (void *zap_)
{
    //  Process ZAP requests forever
    while (true) {
        char *version = s_recv (zap_);
        if (!version)
            break; //  Terminating
        char *sequence = s_recv (zap_);
        char *domain = s_recv (zap_);
        char *address = s_recv (zap_);
        char *routing_id = s_recv (zap_);
        char *mechanism = s_recv (zap_);
        char *username = s_recv (zap_);
        char *password = s_recv (zap_);

        TEST_ASSERT_EQUAL_STRING ("1.0", version);
        TEST_ASSERT_EQUAL_STRING ("PLAIN", mechanism);
        TEST_ASSERT_EQUAL_STRING ("IDENT", routing_id);

        send_string_expect_success (zap_, version, ZMQ_SNDMORE);
        send_string_expect_success (zap_, sequence, ZMQ_SNDMORE);
        if (streq (username, "admin") && streq (password, "password")) {
            send_string_expect_success (zap_, "200", ZMQ_SNDMORE);
            send_string_expect_success (zap_, "OK", ZMQ_SNDMORE);
            send_string_expect_success (zap_, "anonymous", ZMQ_SNDMORE);
            send_string_expect_success (zap_, "", 0);
        } else {
            send_string_expect_success (zap_, "400", ZMQ_SNDMORE);
            send_string_expect_success (zap_, "Invalid username or password",
                                        ZMQ_SNDMORE);
            send_string_expect_success (zap_, "", ZMQ_SNDMORE);
            send_string_expect_success (zap_, "", 0);
        }
        free (version);
        free (sequence);
        free (domain);
        free (address);
        free (routing_id);
        free (mechanism);
        free (username);
        free (password);
    }
    TEST_ASSERT_SUCCESS_ERRNO (zmq_close (zap_));
}

void *zap_thread;

char my_endpoint[MAX_SOCKET_STRING];

static void setup_zap_handler ()
{
    //  Spawn ZAP handler
    //  We create and bind ZAP socket in main thread to avoid case
    //  where child thread does not start up fast enough.
    void *handler = zmq_socket (get_test_context (), ZMQ_REP);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (handler, "inproc://zeromq.zap.01"));
    zap_thread = zmq_threadstart (&zap_handler, handler);
}

static void teardown_zap_handler ()
{
    //  Wait until ZAP handler terminates
    zmq_threadclose (zap_thread);
}

const char domain[] = "test";

void *server;

static void setup_server ()
{
    //  Server socket will accept connections
    server = test_context_socket (ZMQ_DEALER);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (server, ZMQ_ROUTING_ID, "IDENT", 6));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (server, ZMQ_ZAP_DOMAIN, domain, strlen (domain)));
    const int as_server = 1;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (server, ZMQ_PLAIN_SERVER, &as_server, sizeof (int)));
    bind_loopback_ipv4 (server, my_endpoint, sizeof my_endpoint);
}

static void teardown_server ()
{
    test_context_socket_close (server);
}

void setUp ()
{
    setup_test_context ();
    setup_zap_handler ();
    setup_server ();
}

void tearDown ()
{
    teardown_server ();
    teardown_test_context ();
    teardown_zap_handler ();
}

void test_plain_success ()
{
    //  Check PLAIN security with correct username/password
    void *client = test_context_socket (ZMQ_DEALER);
    const char username[] = "admin";
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (client, ZMQ_PLAIN_USERNAME, username, strlen (username)));
    const char password[] = "password";
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (client, ZMQ_PLAIN_PASSWORD, password, strlen (password)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (client, my_endpoint));
    bounce (server, client);
    test_context_socket_close (client);
}

void test_plain_client_as_server_fails ()
{
    //  Check PLAIN security with badly configured client (as_server)
    //  This will be caught by the plain_server class, not passed to ZAP
    void *client = test_context_socket (ZMQ_DEALER);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (client, ZMQ_ZAP_DOMAIN, domain, strlen (domain)));
    const int as_server = 1;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (client, ZMQ_PLAIN_SERVER, &as_server, sizeof (int)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (client, my_endpoint));
    expect_bounce_fail (server, client);
    test_context_socket_close_zero_linger (client);
}

void test_plain_wrong_credentials_fails ()
{
    //  Check PLAIN security -- failed authentication
    void *client = test_context_socket (ZMQ_DEALER);
    const char username[] = "wronguser";
    const char password[] = "wrongpass";
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (client, ZMQ_PLAIN_USERNAME, username, strlen (username)));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (client, ZMQ_PLAIN_PASSWORD, password, strlen (password)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (client, my_endpoint));
    expect_bounce_fail (server, client);
    test_context_socket_close_zero_linger (client);
}

void test_plain_vanilla_socket ()
{
    // Unauthenticated messages from a vanilla socket shouldn't be received
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

//  ZMTP/3.1 greeting with mechanism PLAIN (as-server byte set at index 32)
const uint8_t zmtp_greeting_plain[64] = {
  0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0x7f, 3, 1, 'P', 'L', 'A', 'I',
  'N',  0, 0, 0, 0, 0, 0, 0, 0, 0,    0, 0, 0,   0,   0,   0,
  0,    0, 0, 0, 0, 0, 0, 0, 0, 0,    0, 0, 0,   0,   0,   0};

//  ERROR command body as specified by ZMTP/3.1 (23/ZMTP) for a ZAP status 400
const char plain_error_command[] = "\x05"
                                   "ERROR"
                                   "\x03"
                                   "400";
const size_t plain_error_command_len = sizeof (plain_error_command) - 1;

static void send_all (fd_t fd_, const char *data_, socket_size_t size_)
{
    while (size_ > 0) {
        const int res = send (fd_, data_, size_, 0);
        TEST_ASSERT_GREATER_THAN_INT (0, res);
        size_ -= res;
        data_ += res;
    }
}

static void recv_all (fd_t fd_, char *data_, socket_size_t size_)
{
    while (size_ > 0) {
        const int res = recv (fd_, data_, size_, 0);
        TEST_ASSERT_GREATER_THAN_INT (0, res);
        size_ -= res;
        data_ += res;
    }
}

void test_plain_server_sends_well_formed_error_command ()
{
    //  A raw ZMTP client with wrong credentials must receive an ERROR
    //  command whose name is encoded as "\x05ERROR", not "^RROR"
    fd_t s = connect_socket (my_endpoint);
    send_all (s, reinterpret_cast<const char *> (zmtp_greeting_plain),
              sizeof zmtp_greeting_plain);
    char greeting[64];
    recv_all (s, greeting, sizeof greeting);

    //  HELLO command with credentials the ZAP handler rejects
    const char hello[] = "\x04\x1a\x05"
                         "HELLO"
                         "\x09"
                         "wronguser"
                         "\x09"
                         "wrongpass";
    send_all (s, hello, sizeof hello - 1);

    char header[2];
    recv_all (s, header, sizeof header);
    TEST_ASSERT_EQUAL_HEX8 (0x04, header[0]);
    TEST_ASSERT_EQUAL_INT (plain_error_command_len, header[1]);
    char body[plain_error_command_len];
    recv_all (s, body, sizeof body);
    TEST_ASSERT_EQUAL_MEMORY (plain_error_command, body,
                              plain_error_command_len);
    close (s);
}

void test_plain_client_accepts_well_formed_error_command ()
{
    //  A libzmq client must understand an ERROR command encoded as
    //  "\x05ERROR" by a server that is not libzmq and report the status code
    char server_endpoint[MAX_SOCKET_STRING];
    fd_t listener =
      bind_socket_resolve_port ("127.0.0.1", "0", server_endpoint);
    TEST_ASSERT_SUCCESS_RAW_ERRNO (listen (listener, 1));

    void *client = test_context_socket (ZMQ_DEALER);
    const char username[] = "admin";
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (client, ZMQ_PLAIN_USERNAME, username, strlen (username)));
    const char password[] = "password";
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (client, ZMQ_PLAIN_PASSWORD, password, strlen (password)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_socket_monitor (
      client, "inproc://monitor-plain-client",
      ZMQ_EVENT_HANDSHAKE_SUCCEEDED | ZMQ_EVENT_HANDSHAKE_FAILED_AUTH
        | ZMQ_EVENT_HANDSHAKE_FAILED_PROTOCOL));
    void *client_mon = test_context_socket (ZMQ_PAIR);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_connect (client_mon, "inproc://monitor-plain-client"));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (client, server_endpoint));

    fd_t s = TEST_ASSERT_SUCCESS_RAW_ERRNO (accept (listener, NULL, NULL));

    //  Exchange greetings, the server side announces itself as such
    char greeting[64];
    memcpy (greeting, zmtp_greeting_plain, sizeof greeting);
    greeting[32] = 1;
    send_all (s, greeting, sizeof greeting);
    recv_all (s, greeting, sizeof greeting);

    //  HELLO command: 1 + 5 + 1 + 5 + 1 + 8 bytes
    char hello[2 + 21];
    recv_all (s, hello, sizeof hello);
    TEST_ASSERT_EQUAL_HEX8 (0x04, hello[0]);
    TEST_ASSERT_EQUAL_INT (21, hello[1]);
    TEST_ASSERT_EQUAL_MEMORY ("\x05"
                              "HELLO",
                              hello + 2, 6);

    //  Reject the client with a well-formed ERROR command
    char error_frame[2 + plain_error_command_len];
    error_frame[0] = 0x04;
    error_frame[1] = static_cast<char> (plain_error_command_len);
    memcpy (error_frame + 2, plain_error_command, plain_error_command_len);
    send_all (s, error_frame, sizeof error_frame);

    int err;
    const int event = get_monitor_event (client_mon, &err, NULL);
    TEST_ASSERT_EQUAL_HEX (ZMQ_EVENT_HANDSHAKE_FAILED_AUTH, event);
    TEST_ASSERT_EQUAL_INT (400, err);

    close (s);
    close (listener);
    test_context_socket_close_zero_linger (client_mon);
    test_context_socket_close_zero_linger (client);
}

int main (void)
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_plain_success);
    RUN_TEST (test_plain_client_as_server_fails);
    RUN_TEST (test_plain_wrong_credentials_fails);
    RUN_TEST (test_plain_vanilla_socket);
    RUN_TEST (test_plain_server_sends_well_formed_error_command);
    RUN_TEST (test_plain_client_accepts_well_formed_error_command);
    return UNITY_END ();
}
