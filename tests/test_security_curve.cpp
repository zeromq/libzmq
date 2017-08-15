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
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <stdexcept>
#  define close closesocket
#else
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <unistd.h>
#endif

#include "../src/tweetnacl.h"
#include "../src/curve_client_tools.hpp"
#include "../src/random.hpp"


const char large_identity[] = "0123456789012345678901234567890123456789"
                              "0123456789012345678901234567890123456789"
                              "0123456789012345678901234567890123456789"
                              "0123456789012345678901234567890123456789"
                              "0123456789012345678901234567890123456789"
                              "0123456789012345678901234567890123456789"
                              "012345678901234";

//  We'll generate random test keys at startup
static char valid_client_public [41];
static char valid_client_secret [41];
static char valid_server_public [41];
static char valid_server_secret [41];

void *zap_requests_handled;

#ifdef ZMQ_BUILD_DRAFT_API
//  Read one event off the monitor socket; return value and address
//  by reference, if not null, and event number by value. Returns -1
//  in case of error.

static int
get_monitor_event_internal (void *monitor, int *value, char **address, int recv_flag)
{
    //  First frame in message contains event number and value
    zmq_msg_t msg;
    zmq_msg_init (&msg);
    if (zmq_msg_recv (&msg, monitor, recv_flag) == -1) {
        assert (errno == EAGAIN);
        return -1; //  timed out or no message available
    }
    assert (zmq_msg_more (&msg));

    uint8_t *data = (uint8_t *) zmq_msg_data (&msg);
    uint16_t event = *(uint16_t *) (data);
    if (value)
        *value = *(uint32_t *) (data + 2);

    //  Second frame in message contains event address
    zmq_msg_init (&msg);
    int res = zmq_msg_recv (&msg, monitor, recv_flag) == -1;
    assert (res != -1);
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

int get_monitor_event_with_timeout (void *monitor,
                                    int *value,
                                    char **address,
                                    int timeout)
{
    int res;
    if (timeout == -1) {
        // process infinite timeout in small steps to allow the user
        // to see some information on the console

        int timeout_step = 250;
        int wait_time = 0;
        zmq_setsockopt (monitor, ZMQ_RCVTIMEO, &timeout_step,
                        sizeof (timeout_step));
        while ((res = get_monitor_event_internal (monitor, value, address, 0))
               == -1) {
            wait_time += timeout_step;
            fprintf (stderr, "Still waiting for monitor event after %i ms\n",
                     wait_time);
        }
    } else {
        zmq_setsockopt (monitor, ZMQ_RCVTIMEO, &timeout, sizeof (timeout));
        res = get_monitor_event_internal (monitor, value, address, 0);
    }
    int timeout_infinite = -1;
    zmq_setsockopt (monitor, ZMQ_RCVTIMEO, &timeout_infinite,
                    sizeof (timeout_infinite));
    return res;
}

// assert_* are macros rather than functions, to allow assertion failures be
// attributed to the causing source code line
#define assert_no_more_monitor_events_with_timeout(monitor, timeout)           \
    {                                                                          \
        int event_count = 0;                                                   \
        int event, err;                                                        \
        while ((event = get_monitor_event_with_timeout ((monitor), &err, NULL, \
                                                        (timeout)))            \
               != -1) {                                                        \
            ++event_count;                                                     \
            fprintf (stderr, "Unexpected event: %x (err = %i)\n", event, err); \
        }                                                                      \
        assert (event_count == 0);                                             \
    }

#endif

//  --------------------------------------------------------------------------
//  This methods receives and validates ZAP requests (allowing or denying
//  each client connection).

enum zap_protocol_t
{
  zap_ok,
  // ZAP-compliant non-standard cases
  zap_status_temporary_failure,
  zap_status_internal_error,
  // ZAP protocol errors
  zap_wrong_version,
  zap_wrong_request_id,
  zap_status_invalid,
  zap_too_many_parts
};

static void zap_handler_generic (void *ctx,
                                 zap_protocol_t zap_protocol,
                                 const char *expected_identity = "IDENT")
{
    void *control = zmq_socket (ctx, ZMQ_REQ);
    assert (control);
    int rc = zmq_connect (control, "inproc://handler-control");
    assert (rc == 0);

    void *handler = zmq_socket (ctx, ZMQ_REP);
    assert (handler);
    rc = zmq_bind (handler, "inproc://zeromq.zap.01");
    assert (rc == 0);

    //  Signal main thread that we are ready
    rc = s_send (control, "GO");
    assert (rc == 2);

    zmq_pollitem_t items [] = {
        { control, 0, ZMQ_POLLIN, 0 },
        { handler, 0, ZMQ_POLLIN, 0 },
    };

    //  Process ZAP requests forever
    while (zmq_poll (items, 2, -1) >= 0) {
        if (items [0].revents & ZMQ_POLLIN) {
            char *buf = s_recv (control);
            assert (buf);
            assert (streq (buf, "STOP"));
            free (buf);
            break; //  Terminating - main thread signal
        }
        if (!(items [1].revents & ZMQ_POLLIN))
            continue;

        char *version = s_recv (handler);
        if (!version)
            break; //  Terminating - peer's socket closed

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
        assert (streq (identity, expected_identity));

        s_sendmore (handler, zap_protocol == zap_wrong_version
                               ? "invalid_version"
                               : version);
        s_sendmore (handler, zap_protocol == zap_wrong_request_id
                               ? "invalid_request_id"
                               : sequence);

        if (streq (client_key_text, valid_client_public)) {
            const char *status_code;
            switch (zap_protocol) {
                case zap_status_internal_error:
                    status_code = "500";
                    break;
                case zap_status_temporary_failure:
                    status_code = "300";
                    break;
                case zap_status_invalid:
                    status_code = "invalid_status";
                    break;
                default:
                    status_code = "200";
            }
            s_sendmore (handler, status_code);
            s_sendmore (handler, "OK");
            s_sendmore (handler, "anonymous");
            if (zap_protocol == zap_too_many_parts) {
                s_sendmore (handler, "");
            }
            s_send (handler, "");
        } else {
            s_sendmore (handler, "400");
            s_sendmore (handler, "Invalid client public key");
            s_sendmore (handler, "");
            s_send (handler, "");
        }
        free (version);
        free (sequence);
        free (domain);
        free (address);
        free (identity);
        free (mechanism);

        zmq_atomic_counter_inc (zap_requests_handled);
    }
    rc = zmq_unbind (handler, "inproc://zeromq.zap.01");
    assert (rc == 0);
    close_zero_linger (handler);

    rc = s_send (control, "STOPPED");
    assert (rc == 7);
    close_zero_linger (control);
}

static void zap_handler (void *ctx)
{
    zap_handler_generic (ctx, zap_ok);
}

static void zap_handler_large_identity (void *ctx)
{
    zap_handler_generic (ctx, zap_ok, large_identity);
}

static void zap_handler_wrong_version (void *ctx)
{
    zap_handler_generic (ctx, zap_wrong_version);
}

static void zap_handler_wrong_request_id (void *ctx)
{
    zap_handler_generic (ctx, zap_wrong_request_id);
}

static void zap_handler_wrong_status_invalid (void *ctx)
{
    zap_handler_generic (ctx, zap_status_invalid);
}

static void zap_handler_wrong_status_temporary_failure (void *ctx)
{
    zap_handler_generic (ctx, zap_status_temporary_failure);
}

static void zap_handler_wrong_status_internal_error (void *ctx)
{
    zap_handler_generic (ctx, zap_status_internal_error);
}

static void zap_handler_too_many_parts (void *ctx)
{
    zap_handler_generic (ctx, zap_too_many_parts);
}

void *create_and_connect_curve_client (void *ctx,
                                       char *server_public,
                                       char *client_public,
                                       char *client_secret,
                                       char *my_endpoint)
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

    return client;
}

void expect_new_client_curve_bounce_fail (void *ctx,
                                          char *server_public,
                                          char *client_public,
                                          char *client_secret,
                                          char *my_endpoint,
                                          void *server)
{
    void *client = create_and_connect_curve_client (
      ctx, server_public, client_public, client_secret, my_endpoint);
    expect_bounce_fail (server, client);
    close_zero_linger (client);
}

#ifdef ZMQ_BUILD_DRAFT_API
//  expects that one or more occurrences of the expected event are received 
//  via the specified socket monitor
//  returns the number of occurrences of the expected event
//  interrupts, if a ZMQ_EVENT_HANDSHAKE_FAILED_NO_DETAIL with EPIPE, ECONNRESET
//  or ECONNABORTED occurs; in this case, 0 is returned
//  this should be investigated further, see 
//  https://github.com/zeromq/libzmq/issues/2644
int expect_monitor_event_multiple (void *server_mon,
                                   int expected_event,
                                   int expected_err = -1)
{
    int count_of_expected_events = 0;
    int client_closed_connection = 0;
    //  infinite timeout at the start
    int timeout = -1;

    int event;
    int err;
    while (
      (event = get_monitor_event_with_timeout (server_mon, &err, NULL, timeout))
      != -1) {
        timeout = 250;

        // ignore errors with EPIPE/ECONNRESET/ECONNABORTED, which can happen
        // ECONNRESET can happen on very slow machines, when the engine writes
        // to the peer and then tries to read the socket before the peer reads
        // ECONNABORTED happens when a client aborts a connection via RST/timeout
        if (event == ZMQ_EVENT_HANDSHAKE_FAILED_NO_DETAIL &&
                (err == EPIPE || err == ECONNRESET || err == ECONNABORTED)) {
            fprintf (
              stderr,
              "Ignored event (skipping any further events): %x (err = %i)\n",
              event, err);
            client_closed_connection = 1;
            break;
        }
        if (event != expected_event
            || (-1 != expected_err && err != expected_err)) {
            fprintf (stderr, "Unexpected event: %x (err = %i)\n", event, err);
            assert (false);
        }
        ++count_of_expected_events;
    }
    assert (count_of_expected_events > 0 || client_closed_connection);

    return count_of_expected_events;
}
#endif

void test_garbage_key(void *ctx,
                       void *server,
                       void *server_mon,
                       char *my_endpoint,
                       char *server_public,
                       char *client_public,
                       char *client_secret)
{
    expect_new_client_curve_bounce_fail (ctx, server_public, client_public,
                                         client_secret, my_endpoint, server);

#ifdef ZMQ_BUILD_DRAFT_API
    int handshake_failed_encryption_event_count =
      expect_monitor_event_multiple (server_mon,
                                     ZMQ_EVENT_HANDSHAKE_FAILED_ENCRYPTION);

    // handshake_failed_encryption_event_count should be at least two because 
    // expect_bounce_fail involves two exchanges
    // however, with valgrind we see only one event (maybe the next one takes 
    // very long, or does not happen at all because something else takes very 
    // long)

    fprintf (stderr,
             "count of ZMQ_EVENT_HANDSHAKE_FAILED_ENCRYPTION events: %i\n",
             handshake_failed_encryption_event_count);
#endif
}

void setup_context_and_server_side (void **ctx,
                                    void **handler,
                                    void **zap_thread,
                                    void **server,
                                    void **server_mon,
                                    char *my_endpoint,
                                    zmq_thread_fn zap_handler_ = &zap_handler,
                                    const char *identity = "IDENT")
{
    *ctx = zmq_ctx_new ();
    assert (*ctx);

    //  Spawn ZAP handler
    zap_requests_handled = zmq_atomic_counter_new ();
    assert (zap_requests_handled != NULL);

    *handler = zmq_socket (*ctx, ZMQ_REP);
    assert (*handler);
    int rc = zmq_bind (*handler, "inproc://handler-control");
    assert (rc == 0);

    *zap_thread = zmq_threadstart (zap_handler_, *ctx);

    char *buf = s_recv (*handler);
    assert (buf);
    assert (streq (buf, "GO"));
    free (buf);

    //  Server socket will accept connections
    *server = zmq_socket (*ctx, ZMQ_DEALER);
    assert (*server);

    int as_server = 1;
    rc = zmq_setsockopt (*server, ZMQ_CURVE_SERVER, &as_server, sizeof (int));
    assert (rc == 0);

    rc = zmq_setsockopt (*server, ZMQ_CURVE_SECRETKEY, valid_server_secret, 41);
    assert (rc == 0);

    rc = zmq_setsockopt (*server, ZMQ_IDENTITY, identity, strlen(identity));
    assert (rc == 0);

    rc = zmq_bind (*server, "tcp://127.0.0.1:*");
    assert (rc == 0);

    size_t len = MAX_SOCKET_STRING;
    rc = zmq_getsockopt (*server, ZMQ_LAST_ENDPOINT, my_endpoint, &len);
    assert (rc == 0);

#ifdef ZMQ_BUILD_DRAFT_API
    char monitor_endpoint [] = "inproc://monitor-server";

    //  Monitor handshake events on the server
    rc = zmq_socket_monitor (
      *server, monitor_endpoint,
      ZMQ_EVENT_HANDSHAKE_SUCCEEDED | ZMQ_EVENT_HANDSHAKE_FAILED_NO_DETAIL
        | ZMQ_EVENT_HANDSHAKE_FAILED_ZAP | ZMQ_EVENT_HANDSHAKE_FAILED_ZMTP
        | ZMQ_EVENT_HANDSHAKE_FAILED_ENCRYPTION);
    assert (rc == 0);

    //  Create socket for collecting monitor events
    *server_mon = zmq_socket (*ctx, ZMQ_PAIR);
    assert (*server_mon);

    //  Connect it to the inproc endpoints so they'll get events
    rc = zmq_connect (*server_mon, monitor_endpoint);
    assert (rc == 0);
#endif
}

void shutdown_context_and_server_side (void *ctx,
                                       void *zap_thread,
                                       void *server,
                                       void *server_mon,
                                       void *handler)
{
    int rc = s_send (handler, "STOP");
    assert (rc == 4);
    char *buf = s_recv (handler);
    assert (buf);
    assert (streq (buf, "STOPPED"));
    free (buf);
    rc = zmq_unbind (handler, "inproc://handler-control");
    assert (rc == 0);
    close_zero_linger (handler);

#ifdef ZMQ_BUILD_DRAFT_API
    close_zero_linger (server_mon);
#endif
    close_zero_linger (server);

    //  Wait until ZAP handler terminates
    zmq_threadclose (zap_thread);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    zmq_atomic_counter_destroy (&zap_requests_handled);
}

void test_curve_security_with_valid_credentials (
  void *ctx, char *my_endpoint, void *server, void *server_mon, int timeout)
{
    void *client = create_and_connect_curve_client (
      ctx, valid_server_public, valid_client_public, valid_client_secret, my_endpoint);
    bounce (server, client);
    int rc = zmq_close (client);
    assert (rc == 0);

#ifdef ZMQ_BUILD_DRAFT_API
    int event = get_monitor_event_with_timeout (server_mon, NULL, NULL, -1);
    assert (event == ZMQ_EVENT_HANDSHAKE_SUCCEEDED);

    assert_no_more_monitor_events_with_timeout (server_mon, timeout);
#endif
}

void test_curve_security_with_bogus_client_credentials (
  void *ctx, char *my_endpoint, void *server, void *server_mon, int timeout)
{
    //  This must be caught by the ZAP handler
    char bogus_public [41];
    char bogus_secret [41];
    zmq_curve_keypair (bogus_public, bogus_secret);

    expect_new_client_curve_bounce_fail (ctx, valid_server_public, bogus_public,
                                         bogus_secret, my_endpoint, server);

    int event_count = 0;
#ifdef ZMQ_BUILD_DRAFT_API
    // TODO add another event type ZMQ_EVENT_HANDSHAKE_FAILED_AUTH for this case?
    event_count = expect_monitor_event_multiple (
      server_mon, ZMQ_EVENT_HANDSHAKE_FAILED_NO_DETAIL, EACCES);
    assert (event_count <= 1);
#endif

    // there may be more than one ZAP request due to repeated attempts by the client
    assert (0 == event_count
            || 1 <= zmq_atomic_counter_value (zap_requests_handled));
}

void expect_zmtp_failure (void *client, char *my_endpoint, void *server, void *server_mon)
{
    //  This must be caught by the curve_server class, not passed to ZAP
    int rc = zmq_connect (client, my_endpoint);
    assert (rc == 0);
    expect_bounce_fail (server, client);
    close_zero_linger (client);

#ifdef ZMQ_BUILD_DRAFT_API
    expect_monitor_event_multiple (server_mon, ZMQ_EVENT_HANDSHAKE_FAILED_ZMTP);
#endif

    assert (0 == zmq_atomic_counter_value (zap_requests_handled));
}

void test_curve_security_with_null_client_credentials (void *ctx,
                                                       char *my_endpoint,
                                                       void *server,
                                                       void *server_mon)
{
    void *client = zmq_socket (ctx, ZMQ_DEALER);
    assert (client);

    expect_zmtp_failure (client, my_endpoint, server, server_mon);
}

void test_curve_security_with_plain_client_credentials (void *ctx,
                                                        char *my_endpoint,
                                                        void *server,
                                                        void *server_mon)
{
    void *client = zmq_socket (ctx, ZMQ_DEALER);
    assert (client);
    int rc = zmq_setsockopt (client, ZMQ_PLAIN_USERNAME, "admin", 5);
    assert (rc == 0);
    rc = zmq_setsockopt (client, ZMQ_PLAIN_PASSWORD, "password", 8);
    assert (rc == 0);

    expect_zmtp_failure (client, my_endpoint, server, server_mon);
}

int connect_vanilla_socket (char *my_endpoint)
{
    int s;
    struct sockaddr_in ip4addr;

    unsigned short int port;
    int rc = sscanf (my_endpoint, "tcp://127.0.0.1:%hu", &port);
    assert (rc == 1);

    ip4addr.sin_family = AF_INET;
    ip4addr.sin_port = htons (port);
#if defined(ZMQ_HAVE_WINDOWS) && (_WIN32_WINNT < 0x0600)
    ip4addr.sin_addr.s_addr = inet_addr ("127.0.0.1");
#else
    inet_pton (AF_INET, "127.0.0.1", &ip4addr.sin_addr);
#endif

    s = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
    rc = connect (s, (struct sockaddr *) &ip4addr, sizeof (ip4addr));
    assert (rc > -1);
    return s;
}

void test_curve_security_unauthenticated_message (char *my_endpoint,
                                                  void *server,
                                                  int timeout)
{
    // Unauthenticated messages from a vanilla socket shouldn't be received
    int s = connect_vanilla_socket(my_endpoint);
    // send anonymous ZMTP/1.0 greeting
    send (s, "\x01\x00", 2, 0);
    // send sneaky message that shouldn't be received
    send (s, "\x08\x00sneaky\0", 9, 0);

    zmq_setsockopt (server, ZMQ_RCVTIMEO, &timeout, sizeof (timeout));
    char *buf = s_recv (server);
    if (buf != NULL) {
        printf ("Received unauthenticated message: %s\n", buf);
        assert (buf == NULL);
    }
    close (s);
}

void send_all (int fd, const char *data, size_t size)
{
    while (size > 0) {
        int res = send (fd, data, size, 0);
        assert (res > 0);
        size -= res;
        data += res;
    }
}

template <size_t N> void send (int fd, const char (&data) [N])
{
    send_all (fd, data, N - 1);
}

void send_greeting(int s)
{
    send (s, "\xff\0\0\0\0\0\0\0\0\x7f"); // signature
    send (s, "\x03\x00"); // version 3.0
    send (s, "CURVE\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"); // mechanism CURVE
    send (s, "\0"); // as-server == false
    send (s, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
}

void test_curve_security_invalid_hello_wrong_length (char *my_endpoint,
                                                     void *server,
                                                     void *server_mon,
                                                     int timeout)
{
    int s = connect_vanilla_socket (my_endpoint);

    // send GREETING
    send_greeting (s);

    // send CURVE HELLO of wrong size
    send(s, "\x04\x05HELLO");

#ifdef ZMQ_BUILD_DRAFT_API
    expect_monitor_event_multiple (server_mon, ZMQ_EVENT_HANDSHAKE_FAILED_ZMTP,
                                   EPROTO);
#endif

    close (s);
}

const size_t hello_length = 200;
const size_t welcome_length = 168;

zmq::curve_client_tools_t make_curve_client_tools ()
{
    uint8_t valid_client_secret_decoded[32];
    uint8_t valid_client_public_decoded[32];

    zmq_z85_decode (valid_client_public_decoded, valid_client_public);
    zmq_z85_decode (valid_client_secret_decoded, valid_client_secret);

    uint8_t valid_server_public_decoded[32];
    zmq_z85_decode (valid_server_public_decoded, valid_server_public);

    return zmq::curve_client_tools_t (valid_client_public_decoded,
                                      valid_client_secret_decoded,
                                      valid_server_public_decoded);
}

#ifndef htonll
uint64_t htonll (uint64_t value)
{
    // The answer is 42
    static const int num = 42;

    // Check the endianness
    if (*reinterpret_cast<const char *> (&num) == num) {
        const uint32_t high_part = htonl (static_cast<uint32_t> (value >> 32));
        const uint32_t low_part =
          htonl (static_cast<uint32_t> (value & 0xFFFFFFFFLL));

        return (static_cast<uint64_t> (low_part) << 32) | high_part;
    } else {
        return value;
    }
}
#endif

template <size_t N> void send_command (int s, char (&command)[N])
{
  if (N < 256) {
    send(s, "\x04");
    char len = (char)N;
    send_all(s, &len, 1);
  } else {
    send(s, "\x06");
    uint64_t len = htonll (N);
    send_all (s, (char*)&len, 8);
  }
  send_all (s, command, N);
}

void test_curve_security_invalid_hello_command_name (char *my_endpoint,
                                                     void *server,
                                                     void *server_mon,
                                                     int timeout)
{
    int s = connect_vanilla_socket (my_endpoint);

    send_greeting (s);

    zmq::curve_client_tools_t tools = make_curve_client_tools ();

    // send CURVE HELLO with a misspelled command name (but otherwise correct)
    char hello[hello_length];
    int rc = tools.produce_hello (hello, 0);
    assert (rc == 0);
    hello[5] = 'X';

    send_command(s, hello);

#ifdef ZMQ_BUILD_DRAFT_API
    expect_monitor_event_multiple (server_mon, ZMQ_EVENT_HANDSHAKE_FAILED_ZMTP,
                                   EPROTO);
#endif

    close (s);
}

void test_curve_security_invalid_hello_version (char *my_endpoint,
                                                void *server,
                                                void *server_mon,
                                                int timeout)
{
    int s = connect_vanilla_socket (my_endpoint);

    send_greeting (s);

    zmq::curve_client_tools_t tools = make_curve_client_tools ();

    // send CURVE HELLO with a wrong version number (but otherwise correct)
    char hello[hello_length];
    int rc = tools.produce_hello (hello, 0);
    assert (rc == 0);
    hello[6] = 2;

    send_command (s, hello);

#ifdef ZMQ_BUILD_DRAFT_API
    expect_monitor_event_multiple (server_mon, ZMQ_EVENT_HANDSHAKE_FAILED_ZMTP,
                                   EPROTO);
#endif

    close (s);
}

void flush_read(int fd)
{
    int res;
    char buf[256];

    while ((res = recv (fd, buf, 256, 0)) == 256) {
    }
    assert (res != -1);
}

void recv_all(int fd, uint8_t *data, size_t len)
{
  size_t received = 0;
  while (received < len)
  {
    int res = recv(fd, (char*)data, len, 0);
    assert(res > 0);

    data += res;
    received += res;
  }
}

void recv_greeting (int fd)
{
    uint8_t greeting[64];
    recv_all (fd, greeting, 64);
    //  TODO assert anything about the greeting received from the server?
}

int connect_exchange_greeting_and_send_hello (char *my_endpoint,
                                     zmq::curve_client_tools_t &tools)
{
    int s = connect_vanilla_socket (my_endpoint);

    send_greeting (s);
    recv_greeting (s);

    // send valid CURVE HELLO
    char hello[hello_length];
    int rc = tools.produce_hello (hello, 0);
    assert (rc == 0);

    send_command (s, hello);
    return s;
}

void test_curve_security_invalid_initiate_length (char *my_endpoint,
                                                  void *server,
                                                  void *server_mon,
                                                  int timeout)
{
    zmq::curve_client_tools_t tools = make_curve_client_tools ();

    int s = connect_exchange_greeting_and_send_hello (my_endpoint, tools);

    // receive but ignore WELCOME
    flush_read (s);

#ifdef ZMQ_BUILD_DRAFT_API
    int res = get_monitor_event_with_timeout (server_mon, NULL, NULL, timeout);
    assert (res == -1);
#endif

    send(s, "\x04\x08INITIATE");

#ifdef ZMQ_BUILD_DRAFT_API
    expect_monitor_event_multiple (server_mon, ZMQ_EVENT_HANDSHAKE_FAILED_ZMTP,
                                   EPROTO);
#endif

    close (s);
}

int connect_exchange_greeting_and_hello_welcome (
  char *my_endpoint,
  void *server_mon,
  int timeout,
  zmq::curve_client_tools_t &tools)
{
    int s = connect_exchange_greeting_and_send_hello (
      my_endpoint, tools);

    // receive but ignore WELCOME
    uint8_t welcome[welcome_length + 2];
    recv_all (s, welcome, welcome_length + 2);
    
    int res = tools.process_welcome (welcome + 2, welcome_length);
    assert (res == 0);

#ifdef ZMQ_BUILD_DRAFT_API
    res = get_monitor_event_with_timeout (server_mon, NULL, NULL, timeout);
    assert (res == -1);
#endif

    return s;
}

void test_curve_security_invalid_initiate_command_name (char *my_endpoint,
                                                        void *server,
                                                        void *server_mon,
                                                        int timeout)
{
    zmq::curve_client_tools_t tools = make_curve_client_tools ();
    int s = connect_exchange_greeting_and_hello_welcome (
      my_endpoint, server_mon, timeout, tools);

    char initiate [257];
    tools.produce_initiate (initiate, 257, 1, NULL, 0);
    // modify command name
    initiate[5] = 'X';

    send_command (s, initiate);

#ifdef ZMQ_BUILD_DRAFT_API
    expect_monitor_event_multiple (server_mon, ZMQ_EVENT_HANDSHAKE_FAILED_ZMTP,
                                   EPROTO);
#endif

    close (s);
}

void test_curve_security_invalid_initiate_command_encrypted_cookie (
  char *my_endpoint, void *server, void *server_mon, int timeout)
{
    zmq::curve_client_tools_t tools = make_curve_client_tools ();
    int s = connect_exchange_greeting_and_hello_welcome (
      my_endpoint, server_mon, timeout, tools);

    char initiate [257];
    tools.produce_initiate (initiate, 257, 1, NULL, 0);
    // make garbage from encrypted cookie
    initiate[30] = !initiate[30];

    send_command (s, initiate);

#ifdef ZMQ_BUILD_DRAFT_API
    expect_monitor_event_multiple (
      server_mon, ZMQ_EVENT_HANDSHAKE_FAILED_ENCRYPTION, EPROTO);
#endif

    close (s);
}

void test_curve_security_invalid_initiate_command_encrypted_content (
  char *my_endpoint, void *server, void *server_mon, int timeout)
{
    zmq::curve_client_tools_t tools = make_curve_client_tools ();
    int s = connect_exchange_greeting_and_hello_welcome (
      my_endpoint, server_mon, timeout, tools);

    char initiate [257];
    tools.produce_initiate (initiate, 257, 1, NULL, 0);
    // make garbage from encrypted content
    initiate[150] = !initiate[150];

    send_command (s, initiate);

#ifdef ZMQ_BUILD_DRAFT_API
    expect_monitor_event_multiple (
      server_mon, ZMQ_EVENT_HANDSHAKE_FAILED_ENCRYPTION, EPROTO);
#endif

    close (s);
}

void test_curve_security_zap_unsuccessful (void *ctx,
                                           char *my_endpoint,
                                           void *server,
                                           void *server_mon,
                                           int expected_event,
                                           int expected_err)
{
    expect_new_client_curve_bounce_fail (
      ctx, valid_server_public, valid_client_public, valid_client_secret,
      my_endpoint, server);

    int events_received = 0;
#ifdef ZMQ_BUILD_DRAFT_API
    events_received =
      expect_monitor_event_multiple (server_mon, expected_event, expected_err);
#endif

    // there may be more than one ZAP request due to repeated attempts by the client
    assert (events_received == 0
            || 1 <= zmq_atomic_counter_value (zap_requests_handled));
}

void test_curve_security_zap_protocol_error (void *ctx,
                                             char *my_endpoint,
                                             void *server,
                                             void *server_mon)
{
    test_curve_security_zap_unsuccessful (ctx, my_endpoint, server, server_mon,
#ifdef ZMQ_BUILD_DRAFT_API
                                          ZMQ_EVENT_HANDSHAKE_FAILED_ZAP, EPROTO
#else
                                          0, 0
#endif
    );
}

void test_curve_security_invalid_keysize (void *ctx)
{
    //  Check return codes for invalid buffer sizes
    void *client = zmq_socket (ctx, ZMQ_DEALER);
    assert (client);
    errno = 0;
    int rc = zmq_setsockopt (client, ZMQ_CURVE_SERVERKEY, valid_server_public, 123);
    assert (rc == -1 && errno == EINVAL);
    errno = 0;
    rc = zmq_setsockopt (client, ZMQ_CURVE_PUBLICKEY, valid_client_public, 123);
    assert (rc == -1 && errno == EINVAL);
    errno = 0;
    rc = zmq_setsockopt (client, ZMQ_CURVE_SECRETKEY, valid_client_secret, 123);
    assert (rc == -1 && errno == EINVAL);
    rc = zmq_close (client);
    assert (rc == 0);
}

int main (void)
{
    if (!zmq_has ("curve")) {
        printf ("CURVE encryption not installed, skipping test\n");
        return 0;
    }

    zmq::random_open ();

    //  Generate new keypairs for these tests
    int rc = zmq_curve_keypair (valid_client_public, valid_client_secret);
    assert (rc == 0);
    rc = zmq_curve_keypair (valid_server_public, valid_server_secret);
    assert (rc == 0);

    int timeout = 250;

    setup_test_environment ();

    void *ctx;
    void *handler;
    void *zap_thread;
    void *server;
    void *server_mon;
    char my_endpoint [MAX_SOCKET_STRING];

#if 0
    fprintf (stderr, "test_curve_security_with_valid_credentials\n");
    setup_context_and_server_side (&ctx, &handler, &zap_thread, &server,
                                   &server_mon, my_endpoint);
    test_curve_security_with_valid_credentials (ctx, my_endpoint, server,
                                                server_mon, timeout);
    shutdown_context_and_server_side (ctx, zap_thread, server, server_mon,
            handler);

    char garbage_key [] = "0000000000000000000000000000000000000000";

    //  Check CURVE security with a garbage server key
    //  This will be caught by the curve_server class, not passed to ZAP
    fprintf (stderr, "test_garbage_server_key\n");
    setup_context_and_server_side (&ctx, &handler, &zap_thread, &server,
                                   &server_mon, my_endpoint);
    test_garbage_key (ctx, server, server_mon, my_endpoint, garbage_key,
                      valid_client_public, valid_client_secret);
    shutdown_context_and_server_side (ctx, zap_thread, server, server_mon,
            handler);

    //  Check CURVE security with a garbage client public key
    //  This will be caught by the curve_server class, not passed to ZAP
    fprintf (stderr, "test_garbage_client_public_key\n");
    setup_context_and_server_side (&ctx, &handler, &zap_thread, &server,
                                   &server_mon, my_endpoint);
    test_garbage_key (ctx, server, server_mon, my_endpoint, valid_server_public,
                      garbage_key, valid_client_secret);
    shutdown_context_and_server_side (ctx, zap_thread, server, server_mon,
            handler);

    //  Check CURVE security with a garbage client secret key
    //  This will be caught by the curve_server class, not passed to ZAP
    fprintf (stderr, "test_garbage_client_secret_key\n");
    setup_context_and_server_side (&ctx, &handler, &zap_thread, &server,
                                   &server_mon, my_endpoint);
    test_garbage_key (ctx, server, server_mon, my_endpoint, valid_server_public,
                      valid_client_public, garbage_key);
    shutdown_context_and_server_side (ctx, zap_thread, server, server_mon,
            handler);

    fprintf (stderr, "test_curve_security_with_bogus_client_credentials\n");
    setup_context_and_server_side (&ctx, &handler, &zap_thread, &server,
                                   &server_mon, my_endpoint);
    test_curve_security_with_bogus_client_credentials (ctx, my_endpoint, server,
                                                       server_mon, timeout);
    shutdown_context_and_server_side (ctx, zap_thread, server, server_mon,
            handler);

    fprintf (stderr, "test_curve_security_with_null_client_credentials\n");
    setup_context_and_server_side (&ctx, &handler, &zap_thread, &server,
                                   &server_mon, my_endpoint);
    test_curve_security_with_null_client_credentials (ctx, my_endpoint, server,
                                                      server_mon);
    shutdown_context_and_server_side (ctx, zap_thread, server, server_mon,
            handler);

    fprintf (stderr, "test_curve_security_with_plain_client_credentials\n");
    setup_context_and_server_side (&ctx, &handler, &zap_thread, &server,
                                   &server_mon, my_endpoint);
    test_curve_security_with_plain_client_credentials (ctx, my_endpoint, server,
                                                       server_mon);
    shutdown_context_and_server_side (ctx, zap_thread, server, server_mon,
            handler);

    fprintf (stderr, "test_curve_security_unauthenticated_message\n");
    setup_context_and_server_side (&ctx, &handler, &zap_thread, &server,
                                   &server_mon, my_endpoint);
    test_curve_security_unauthenticated_message (my_endpoint, server, timeout);
    shutdown_context_and_server_side (ctx, zap_thread, server, server_mon,
            handler);

    //  Invalid ZAP protocol tests

    //  wrong version
    fprintf (stderr, "test_curve_security_zap_protocol_error wrong_version\n");
    setup_context_and_server_side (&ctx, &handler, &zap_thread, &server,
                                   &server_mon, my_endpoint,
                                   &zap_handler_wrong_version);
    test_curve_security_zap_protocol_error (ctx, my_endpoint, server,
                                            server_mon);
    shutdown_context_and_server_side (ctx, zap_thread, server, server_mon,
            handler);

    //  wrong request id
    fprintf (stderr, "test_curve_security_zap_protocol_error wrong_request_id\n");
    setup_context_and_server_side (&ctx, &handler, &zap_thread, &server,
                                   &server_mon, my_endpoint,
                                   &zap_handler_wrong_request_id);
    test_curve_security_zap_protocol_error (ctx, my_endpoint, server,
                                            server_mon);
    shutdown_context_and_server_side (ctx, zap_thread, server, server_mon,
            handler);

    //  status invalid (not a 3-digit number)
    fprintf (stderr, "test_curve_security_zap_protocol_error wrong_status_invalid\n");
    setup_context_and_server_side (&ctx, &handler, &zap_thread, &server,
                                   &server_mon, my_endpoint,
                                   &zap_handler_wrong_status_invalid);
    test_curve_security_zap_protocol_error (ctx, my_endpoint, server,
                                            server_mon);
    shutdown_context_and_server_side (ctx, zap_thread, server, server_mon,
            handler);

    //  too many parts
    fprintf (stderr, "test_curve_security_zap_protocol_error too_many_parts\n");
    setup_context_and_server_side (&ctx, &handler, &zap_thread, &server,
                                   &server_mon, my_endpoint,
                                   &zap_handler_too_many_parts);
    test_curve_security_zap_protocol_error (ctx, my_endpoint, server,
                                            server_mon);
    shutdown_context_and_server_side (ctx, zap_thread, server, server_mon,
            handler);

    //  ZAP non-standard cases

    //  TODO make these observable on the client side as well (they are 
    //  transmitted as an ERROR message)

    //  status 300 temporary failure
    fprintf (stderr, "test_curve_security_zap_unsuccessful status 300\n");
    setup_context_and_server_side (&ctx, &handler, &zap_thread, &server,
                                   &server_mon, my_endpoint,
                                   &zap_handler_wrong_status_temporary_failure);
    test_curve_security_zap_unsuccessful (ctx, my_endpoint, server, server_mon,
#ifdef ZMQ_BUILD_DRAFT_API
                                          ZMQ_EVENT_HANDSHAKE_FAILED_NO_DETAIL,
                                          EAGAIN
#else
                                          0, 0
#endif
    );
    shutdown_context_and_server_side (ctx, zap_thread, server, server_mon,
            handler);

    //  status 500 internal error
    fprintf (stderr, "test_curve_security_zap_unsuccessful status 500\n");
    setup_context_and_server_side (&ctx, &handler, &zap_thread, &server,
                                   &server_mon, my_endpoint,
                                   &zap_handler_wrong_status_internal_error);
    test_curve_security_zap_unsuccessful (ctx, my_endpoint, server, server_mon,
#ifdef ZMQ_BUILD_DRAFT_API
                                          ZMQ_EVENT_HANDSHAKE_FAILED_NO_DETAIL,
                                          EFAULT
#else
                                          0, 0
#endif
    );
    shutdown_context_and_server_side (ctx, zap_thread, server, server_mon,
            handler);

    fprintf (stderr, "test_curve_security_invalid_hello_wrong_length\n");
    setup_context_and_server_side (&ctx, &handler, &zap_thread, &server,
                                   &server_mon, my_endpoint);
    test_curve_security_invalid_hello_wrong_length (my_endpoint, server,
                                                    server_mon, timeout);
    shutdown_context_and_server_side (ctx, zap_thread, server, server_mon,
                                      handler);
    fprintf (stderr, "test_curve_security_invalid_hello_command_name\n");
    setup_context_and_server_side (&ctx, &handler, &zap_thread, &server,
                                   &server_mon, my_endpoint);
    test_curve_security_invalid_hello_command_name (my_endpoint, server,
                                                    server_mon, timeout);
    shutdown_context_and_server_side (ctx, zap_thread, server, server_mon,
                                      handler);

    fprintf (stderr, "test_curve_security_invalid_hello_command_version\n");
    setup_context_and_server_side (&ctx, &handler, &zap_thread, &server,
                                   &server_mon, my_endpoint);
    test_curve_security_invalid_hello_version (my_endpoint, server, server_mon,
                                               timeout);
    shutdown_context_and_server_side (ctx, zap_thread, server, server_mon,
                                      handler);

    fprintf (stderr, "test_curve_security_invalid_initiate_command_length\n");
    setup_context_and_server_side (&ctx, &handler, &zap_thread, &server,
                                   &server_mon, my_endpoint);
    test_curve_security_invalid_initiate_length (my_endpoint, server,
                                                 server_mon, timeout);
    shutdown_context_and_server_side (ctx, zap_thread, server, server_mon,
                                      handler);

    fprintf (stderr, "test_curve_security_invalid_initiate_command_name\n");
    setup_context_and_server_side (&ctx, &handler, &zap_thread, &server,
                                   &server_mon, my_endpoint);
    test_curve_security_invalid_initiate_command_name (my_endpoint, server,
                                                       server_mon, timeout);
    shutdown_context_and_server_side (ctx, zap_thread, server, server_mon,
                                      handler);

    fprintf (stderr, "test_curve_security_invalid_initiate_command_encrypted_cookie\n");
    setup_context_and_server_side (&ctx, &handler, &zap_thread, &server,
                                   &server_mon, my_endpoint);
    test_curve_security_invalid_initiate_command_encrypted_cookie (
      my_endpoint, server, server_mon, timeout);
    shutdown_context_and_server_side (ctx, zap_thread, server, server_mon,
                                      handler);

    fprintf (stderr, "test_curve_security_invalid_initiate_command_encrypted_content\n");
    setup_context_and_server_side (&ctx, &handler, &zap_thread, &server,
                                   &server_mon, my_endpoint);
    test_curve_security_invalid_initiate_command_encrypted_content (
      my_endpoint, server, server_mon, timeout);
    shutdown_context_and_server_side (ctx, zap_thread, server, server_mon,
                                      handler);
#endif

    //  test with a large identity (resulting in large metadata)
    fprintf (stderr, "test_curve_security_with_valid_credentials (large identity)\n");
    setup_context_and_server_side (&ctx, &handler, &zap_thread, &server,
                                   &server_mon, my_endpoint, &zap_handler_large_identity, large_identity);
    test_curve_security_with_valid_credentials (ctx, my_endpoint, server,
                                                server_mon, timeout);
    shutdown_context_and_server_side (ctx, zap_thread, server, server_mon,
            handler);

    ctx = zmq_ctx_new ();
    test_curve_security_invalid_keysize (ctx);
    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    zmq::random_close ();

    return 0;
}
