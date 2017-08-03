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
#if defined (ZMQ_HAVE_WINDOWS)
#   include <winsock2.h>
#   include <ws2tcpip.h>
#   include <stdexcept>
#   define close closesocket
#else
#   include <sys/socket.h>
#   include <netinet/in.h>
#   include <arpa/inet.h>
#   include <unistd.h>
#endif

//  We'll generate random test keys at startup
static char client_public [41];
static char client_secret [41];
static char server_public [41];
static char server_secret [41];

#ifdef ZMQ_BUILD_DRAFT_API
//  Read one event off the monitor socket; return value and address
//  by reference, if not null, and event number by value. Returns -1
//  in case of error.

static int
get_monitor_event (void *monitor, int *value, char **address, int recv_flag)
{
    //  First frame in message contains event number and value
    zmq_msg_t msg;
    zmq_msg_init (&msg);
    if (zmq_msg_recv(&msg, monitor, recv_flag) == -1)
    {
        assert(errno == EAGAIN);
        return -1;              //  timed out or no message available
    }
    assert (zmq_msg_more (&msg));

    uint8_t *data = (uint8_t *) zmq_msg_data (&msg);
    uint16_t event = *(uint16_t *) (data);
    if (value)
        *value = *(uint32_t *) (data + 2);

    //  Second frame in message contains event address
    zmq_msg_init (&msg);
    int res = zmq_msg_recv(&msg, monitor, recv_flag) == -1;
    assert(res != -1);
    assert (!zmq_msg_more (&msg));

    if (address) {
        uint8_t *data = (uint8_t *) zmq_msg_data (&msg);
        size_t size = zmq_msg_size (&msg);
        *address = (char *) malloc (size + 1);
        memcpy (*address, data, size);
        *address [size] = 0;
    }
    return event;
}

int get_monitor_event_with_timeout(void *monitor, int *value, char **address, int timeout)
{
    zmq_setsockopt (monitor, ZMQ_RCVTIMEO, &timeout, sizeof(timeout));
    int res = get_monitor_event(monitor, value, address, 0);
    zmq_setsockopt (monitor, ZMQ_RCVTIMEO, 0, 0);
    return res;
}

// assert_* are macros rather than functions, to allow assertion failures be
// attributed to the causing source code line
#define assert_no_more_monitor_events_with_timeout(monitor, timeout)           \
  {                                                                            \
    int event_count = 0;                                                       \
    int event, err;                                                            \
    while ((event = get_monitor_event_with_timeout((monitor), &err, NULL,      \
                                                   (timeout))) != -1) {        \
      ++event_count;                                                           \
      fprintf(stderr, "Unexpected event: %x (err = %i)\n", event, err);        \
    }                                                                          \
    assert(event_count == 0);                                                  \
  }

#define assert_monitor_event(monitor, expected_events)                         \
  {                                                                            \
    int err;                                                                   \
    int event = get_monitor_event(monitor, &err, NULL, 0);                     \
    assert(event != -1);                                                       \
    if ((event & (expected_events)) == 0) {                                    \
      fprintf(stderr, "Unexpected event: %x (err = %i)\n", event, err);        \
      while ((event = get_monitor_event(monitor, NULL, NULL, (timeout))) !=    \
             -1) {                                                             \
        fprintf(stderr, "Further event: %x\n", event);                         \
      }                                                                        \
      assert(false);                                                           \
    }                                                                          \
  }

#endif

//  --------------------------------------------------------------------------
//  This methods receives and validates ZAP requests (allowing or denying
//  each client connection).

static void zap_handler (void *handler)
{
    //  Process ZAP requests forever
    while (true) {
        char *version = s_recv (handler);
        if (!version)
            break;          //  Terminating

        char *sequence = s_recv (handler);
        char *domain = s_recv (handler);
        char *address = s_recv (handler);
        char *identity = s_recv (handler);
        char *mechanism = s_recv (handler);
        uint8_t client_key [32];
        int size = zmq_recv (handler, client_key, 32, 0);
        assert (size == 32);

        char client_key_text [41];
        zmq_z85_encode (client_key_text, client_key, 32);

        assert (streq (version, "1.0"));
        assert (streq (mechanism, "CURVE"));
        assert (streq (identity, "IDENT"));

        s_sendmore (handler, version);
        s_sendmore (handler, sequence);

        if (streq (client_key_text, client_public)) {
            s_sendmore (handler, "200");
            s_sendmore (handler, "OK");
            s_sendmore (handler, "anonymous");
            s_send     (handler, "");
        }
        else {
            s_sendmore (handler, "400");
            s_sendmore (handler, "Invalid client public key");
            s_sendmore (handler, "");
            s_send     (handler, "");
        }
        free (version);
        free (sequence);
        free (domain);
        free (address);
        free (identity);
        free (mechanism);
    }
    zmq_close (handler);
}

void test_garbage_key(void *ctx, void *server, void *server_mon, char *my_endpoint, char *server_public, char *client_public, char *client_secret)
{
    void *client = zmq_socket (ctx, ZMQ_DEALER);
    assert (client);
    int rc = zmq_setsockopt (client, ZMQ_CURVE_SERVERKEY, server_public, 41);
    assert (rc == 0);
    rc = zmq_setsockopt (client, ZMQ_CURVE_PUBLICKEY, client_public, 41);
    assert (rc == 0);
    rc = zmq_setsockopt (client, ZMQ_CURVE_SECRETKEY, client_secret, 41);
    assert (rc == 0);
    rc = zmq_connect (client, my_endpoint);
    assert (rc == 0);
    expect_bounce_fail (server, client);
    close_zero_linger(client);

#ifdef ZMQ_BUILD_DRAFT_API
    int timeout = 250;

    int handshake_failed_encryption_event_count = 0;
    int err;
    int event;
    while ((event = get_monitor_event_with_timeout (server_mon, &err, NULL, timeout)) != -1)
    {
      switch (event)
      {
      case ZMQ_EVENT_HANDSHAKE_FAILED_ENCRYPTION:
        ++handshake_failed_encryption_event_count;
        break;
      case ZMQ_EVENT_HANDSHAKE_FAILED_NO_DETAIL:
        // ignore errors with EPIPE, which happen sporadically
        if (err == EPIPE)
        {
          fprintf (stderr, "Ignored event: %x (err = %i)\n", event, err);
          continue;
        }
      default:
        fprintf (stderr, "Unexpected event: %x (err = %i)\n", event, err);
        assert (false);
      }    
      if (handshake_failed_encryption_event_count == 2)
        break;
    }

    // Two times because expect_bounce_fail involves two exchanges
    assert (handshake_failed_encryption_event_count == 2);

    // Even though the client socket is closed, the server 
    // still handles HELLO messages. Output them for diagnostic purposes.

    do {
        int err;
        event = get_monitor_event_with_timeout (server_mon, &err, NULL, timeout);
        if (event != -1)
        {
          fprintf(stderr, "Flushed event: %x (errno = %i)\n", event, err);
        }
    } while (event != -1);
#endif
}

void setup_context_and_server_side(void **ctx, void **handler, void **zap_thread, void **server, void **server_mon, char *my_endpoint)
{
    *ctx = zmq_ctx_new ();
    assert (*ctx);

    //  Spawn ZAP handler
    //  We create and bind ZAP socket in main thread to avoid case
    //  where child thread does not start up fast enough.
    *handler = zmq_socket (*ctx, ZMQ_REP);
    assert (*handler);
    int rc = zmq_bind (*handler, "inproc://zeromq.zap.01");
    assert (rc == 0);
    *zap_thread = zmq_threadstart (&zap_handler, *handler);

    //  Server socket will accept connections
    *server = zmq_socket (*ctx, ZMQ_DEALER);
    assert (*server);

    int as_server = 1;
    rc = zmq_setsockopt (*server, ZMQ_CURVE_SERVER, &as_server, sizeof (int));
    assert (rc == 0);

    rc = zmq_setsockopt (*server, ZMQ_CURVE_SECRETKEY, server_secret, 41);
    assert (rc == 0);

    rc = zmq_setsockopt (*server, ZMQ_IDENTITY, "IDENT", 6);
    assert (rc == 0);

    rc = zmq_bind (*server, "tcp://127.0.0.1:*");
    assert (rc == 0);

    size_t len = MAX_SOCKET_STRING;
    rc = zmq_getsockopt (*server, ZMQ_LAST_ENDPOINT, my_endpoint, &len);
    assert (rc == 0);

#ifdef ZMQ_BUILD_DRAFT_API
    //  Monitor handshake events on the server
    rc = zmq_socket_monitor (*server, "inproc://monitor-server",
            ZMQ_EVENT_HANDSHAKE_SUCCEEDED | ZMQ_EVENT_HANDSHAKE_FAILED_NO_DETAIL |
            ZMQ_EVENT_HANDSHAKE_FAILED_ZAP |ZMQ_EVENT_HANDSHAKE_FAILED_ZMTP | 
            ZMQ_EVENT_HANDSHAKE_FAILED_ENCRYPTION);
    assert (rc == 0);

    //  Create socket for collecting monitor events
    *server_mon = zmq_socket (*ctx, ZMQ_PAIR);
    assert (*server_mon);

    //  Connect it to the inproc endpoints so they'll get events
    rc = zmq_connect (*server_mon, "inproc://monitor-server");
    assert (rc == 0);
#endif
}

void shutdown_context_and_server_side(void *ctx, void *zap_thread, void *server, void *server_mon)
{
#ifdef ZMQ_BUILD_DRAFT_API
    close_zero_linger (server_mon);
#endif
    int rc = zmq_close (server);
    assert (rc == 0);
    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    //  Wait until ZAP handler terminates
    zmq_threadclose (zap_thread);
}

void test_curve_security_with_valid_credentials(void * ctx, char * my_endpoint, void * server, void * server_mon, int timeout)
{
    void *client = zmq_socket(ctx, ZMQ_DEALER);
    assert(client);
    int rc = zmq_setsockopt(client, ZMQ_CURVE_SERVERKEY, server_public, 41);
    assert(rc == 0);
    rc = zmq_setsockopt(client, ZMQ_CURVE_PUBLICKEY, client_public, 41);
    assert(rc == 0);
    rc = zmq_setsockopt(client, ZMQ_CURVE_SECRETKEY, client_secret, 41);
    assert(rc == 0);
    rc = zmq_connect(client, my_endpoint);
    assert(rc == 0);
    bounce(server, client);
    rc = zmq_close(client);
    assert(rc == 0);

#ifdef ZMQ_BUILD_DRAFT_API
    int event = get_monitor_event(server_mon, NULL, NULL, 0);
    assert(event == ZMQ_EVENT_HANDSHAKE_SUCCEEDED);

    assert_no_more_monitor_events_with_timeout(server_mon, timeout);
#endif
}

void test_curve_security_with_bogus_client_credentials(void * ctx, char * my_endpoint, void * server, void * server_mon, int timeout)
{
  //  This must be caught by the ZAP handler
  char bogus_public[41];
  char bogus_secret[41];
  zmq_curve_keypair(bogus_public, bogus_secret);

  void *client = zmq_socket(ctx, ZMQ_DEALER);
  assert(client);
  int rc = zmq_setsockopt(client, ZMQ_CURVE_SERVERKEY, server_public, 41);
  assert(rc == 0);
  rc = zmq_setsockopt(client, ZMQ_CURVE_PUBLICKEY, bogus_public, 41);
  assert(rc == 0);
  rc = zmq_setsockopt(client, ZMQ_CURVE_SECRETKEY, bogus_secret, 41);
  assert(rc == 0);
  rc = zmq_connect(client, my_endpoint);
  assert(rc == 0);
  expect_bounce_fail(server, client);
  close_zero_linger(client);

#ifdef ZMQ_BUILD_DRAFT_API
  int event = get_monitor_event(server_mon, NULL, NULL, 0);
  // TODO add another event type ZMQ_EVENT_HANDSHAKE_FAILED_AUTH for this case?
  assert(event == ZMQ_EVENT_HANDSHAKE_FAILED_NO_DETAIL); // ZAP handle the error,  not curve_server

  assert_no_more_monitor_events_with_timeout(server_mon, timeout);
#endif
}

void test_curve_security_with_null_client_credentials(void * ctx, char * my_endpoint, void * server, void * server_mon)
{
  //  This must be caught by the curve_server class, not passed to ZAP
  void *client = zmq_socket(ctx, ZMQ_DEALER);
  assert(client);
  int rc = zmq_connect(client, my_endpoint);
  assert(rc == 0);
  expect_bounce_fail(server, client);
  close_zero_linger(client);

#ifdef ZMQ_BUILD_DRAFT_API
  int event = get_monitor_event(server_mon, NULL, NULL, 0);

  assert(event == ZMQ_EVENT_HANDSHAKE_FAILED_ZMTP);
#endif
}

void test_curve_security_with_plain_client_credentials(void * ctx, void * server)
{
  //  This must be caught by the curve_server class, not passed to ZAP
  void *client = zmq_socket(ctx, ZMQ_DEALER);
  assert(client);
  int rc = zmq_setsockopt(client, ZMQ_PLAIN_USERNAME, "admin", 5);
  assert(rc == 0);
  rc = zmq_setsockopt(client, ZMQ_PLAIN_PASSWORD, "password", 8);
  assert(rc == 0);
  rc = zmq_connect(client, "tcp://localhost:9998");
  assert(rc == 0);
  expect_bounce_fail(server, client);
  close_zero_linger(client);
}

void test_curve_security_unauthenticated_message(char * my_endpoint, void * server, int timeout)
{
  // Unauthenticated messages from a vanilla socket shouldn't be received
  struct sockaddr_in ip4addr;
  int s;

  unsigned short int port;
  int rc = sscanf(my_endpoint, "tcp://127.0.0.1:%hu", &port);
  assert(rc == 1);

  ip4addr.sin_family = AF_INET;
  ip4addr.sin_port = htons(port);
#if defined (ZMQ_HAVE_WINDOWS) && (_WIN32_WINNT < 0x0600)
  ip4addr.sin_addr.s_addr = inet_addr("127.0.0.1");
#else
  inet_pton(AF_INET, "127.0.0.1", &ip4addr.sin_addr);
#endif

  s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  rc = connect(s, (struct sockaddr*) &ip4addr, sizeof(ip4addr));
  assert(rc > -1);
  // send anonymous ZMTP/1.0 greeting
  send(s, "\x01\x00", 2, 0);
  // send sneaky message that shouldn't be received
  send(s, "\x08\x00sneaky\0", 9, 0);

  zmq_setsockopt(server, ZMQ_RCVTIMEO, &timeout, sizeof(timeout));
  char *buf = s_recv(server);
  if (buf != NULL) {
    printf("Received unauthenticated message: %s\n", buf);
    assert(buf == NULL);
  }
  close(s);
}

void test_curve_security_invalid_keysize(void * ctx)
{
  //  Check return codes for invalid buffer sizes
  void *client = zmq_socket(ctx, ZMQ_DEALER);
  assert(client);
  errno = 0;
  int rc = zmq_setsockopt(client, ZMQ_CURVE_SERVERKEY, server_public, 123);
  assert(rc == -1 && errno == EINVAL);
  errno = 0;
  rc = zmq_setsockopt(client, ZMQ_CURVE_PUBLICKEY, client_public, 123);
  assert(rc == -1 && errno == EINVAL);
  errno = 0;
  rc = zmq_setsockopt(client, ZMQ_CURVE_SECRETKEY, client_secret, 123);
  assert(rc == -1 && errno == EINVAL);
  rc = zmq_close(client);
  assert(rc == 0);
}

int main(void)
{
    if (!zmq_has("curve"))
    {
      printf("CURVE encryption not installed, skipping test\n");
      return 0;
    }

    //  Generate new keypairs for these tests
    int rc = zmq_curve_keypair (client_public, client_secret);
    assert (rc == 0);
    rc = zmq_curve_keypair (server_public, server_secret);
    assert (rc == 0);

    int timeout = 250;
    
    setup_test_environment ();

    void *ctx;
    void *handler;
    void *zap_thread;
    void *server;
    void *server_mon;
    char my_endpoint[MAX_SOCKET_STRING];

    setup_context_and_server_side (&ctx, &handler, &zap_thread, &server, &server_mon, my_endpoint);
    test_curve_security_with_valid_credentials(ctx, my_endpoint, server, server_mon, timeout);
    shutdown_context_and_server_side(ctx, zap_thread, server, server_mon);

    char garbage_key [] = "0000000000000000000000000000000000000000";

    //  Check CURVE security with a garbage server key
    //  This will be caught by the curve_server class, not passed to ZAP
    fprintf(stderr, "test_garbage_server_key\n");
    setup_context_and_server_side (&ctx, &handler, &zap_thread, &server, &server_mon, my_endpoint);
    test_garbage_key(ctx, server, server_mon, my_endpoint, garbage_key, client_public, client_secret);
    shutdown_context_and_server_side(ctx, zap_thread, server, server_mon);

    //  Check CURVE security with a garbage client public key
    //  This will be caught by the curve_server class, not passed to ZAP
    fprintf(stderr, "test_garbage_client_public_key\n");
    setup_context_and_server_side (&ctx, &handler, &zap_thread, &server, &server_mon, my_endpoint);
    test_garbage_key(ctx, server, server_mon, my_endpoint, server_public, garbage_key, client_secret);
    shutdown_context_and_server_side(ctx, zap_thread, server, server_mon);
    
    //  Check CURVE security with a garbage client secret key
    //  This will be caught by the curve_server class, not passed to ZAP
    fprintf(stderr, "test_garbage_client_secret_key\n");
    setup_context_and_server_side (&ctx, &handler, &zap_thread, &server, &server_mon, my_endpoint);
    test_garbage_key(ctx, server, server_mon, my_endpoint, server_public, client_public, garbage_key);
    shutdown_context_and_server_side(ctx, zap_thread, server, server_mon);
    
    setup_context_and_server_side (&ctx, &handler, &zap_thread, &server, &server_mon, my_endpoint);
    test_curve_security_with_bogus_client_credentials(ctx, my_endpoint, server, server_mon, timeout);
    shutdown_context_and_server_side(ctx, zap_thread, server, server_mon);

    setup_context_and_server_side (&ctx, &handler, &zap_thread, &server, &server_mon, my_endpoint);
    test_curve_security_with_null_client_credentials(ctx, my_endpoint, server, server_mon);
    shutdown_context_and_server_side(ctx, zap_thread, server, server_mon);

    setup_context_and_server_side (&ctx, &handler, &zap_thread, &server, &server_mon, my_endpoint);
    test_curve_security_with_plain_client_credentials(ctx, server);
    shutdown_context_and_server_side(ctx, zap_thread, server, server_mon);

    setup_context_and_server_side (&ctx, &handler, &zap_thread, &server, &server_mon, my_endpoint);
    test_curve_security_unauthenticated_message(my_endpoint, server, timeout);
    shutdown_context_and_server_side(ctx, zap_thread, server, server_mon);

    ctx = zmq_ctx_new();
    test_curve_security_invalid_keysize(ctx);
    rc = zmq_ctx_term(ctx);
    assert (rc == 0);

    return 0;
}
