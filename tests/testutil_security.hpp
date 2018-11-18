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

#ifndef __TESTUTIL_SECURITY_HPP_INCLUDED__
#define __TESTUTIL_SECURITY_HPP_INCLUDED__

#include "testutil.hpp"

//  security test utils

typedef void(socket_config_fn) (void *, void *);

const char *test_zap_domain = "ZAPTEST";

//  NULL specific functions
void socket_config_null_client (void *server_, void *server_secret_)
{
    LIBZMQ_UNUSED (server_);
    LIBZMQ_UNUSED (server_secret_);
}

void socket_config_null_server (void *server_, void *server_secret_)
{
    int rc = zmq_setsockopt (server_, ZMQ_ZAP_DOMAIN, test_zap_domain,
                             strlen (test_zap_domain));
    assert (rc == 0);
#ifdef ZMQ_ZAP_ENFORCE_DOMAIN
    int required = server_secret_ ? *(int *) server_secret_ : 0;
    rc =
      zmq_setsockopt (server_, ZMQ_ZAP_ENFORCE_DOMAIN, &required, sizeof (int));
    assert (rc == 0);
#else
    LIBZMQ_UNUSED (server_secret_);
#endif
}

//  PLAIN specific functions
const char *test_plain_username = "testuser";
const char *test_plain_password = "testpass";

void socket_config_plain_client (void *server_, void *server_secret_)
{
    LIBZMQ_UNUSED (server_secret_);

    int rc =
      zmq_setsockopt (server_, ZMQ_PLAIN_PASSWORD, test_plain_password, 8);
    assert (rc == 0);

    rc = zmq_setsockopt (server_, ZMQ_PLAIN_USERNAME, test_plain_username, 8);
    assert (rc == 0);
}

void socket_config_plain_server (void *server_, void *server_secret_)
{
    LIBZMQ_UNUSED (server_secret_);

    int as_server = 1;
    int rc =
      zmq_setsockopt (server_, ZMQ_PLAIN_SERVER, &as_server, sizeof (int));
    assert (rc == 0);

    rc = zmq_setsockopt (server_, ZMQ_ZAP_DOMAIN, test_zap_domain,
                         strlen (test_zap_domain));
    assert (rc == 0);
}

//  CURVE specific functions

//  We'll generate random test keys at startup
char valid_client_public[41];
char valid_client_secret[41];
char valid_server_public[41];
char valid_server_secret[41];

void setup_testutil_security_curve ()
{
    //  Generate new keypairs for these tests
    int rc = zmq_curve_keypair (valid_client_public, valid_client_secret);
    assert (rc == 0);
    rc = zmq_curve_keypair (valid_server_public, valid_server_secret);
    assert (rc == 0);
}

void socket_config_curve_server (void *server_, void *server_secret_)
{
    int as_server = 1;
    int rc =
      zmq_setsockopt (server_, ZMQ_CURVE_SERVER, &as_server, sizeof (int));
    assert (rc == 0);

    rc = zmq_setsockopt (server_, ZMQ_CURVE_SECRETKEY, server_secret_, 41);
    assert (rc == 0);

    rc = zmq_setsockopt (server_, ZMQ_ZAP_DOMAIN, test_zap_domain,
                         strlen (test_zap_domain));
    assert (rc == 0);

#ifdef ZMQ_ZAP_ENFORCE_DOMAIN
    int required = 1;
    rc =
      zmq_setsockopt (server_, ZMQ_ZAP_ENFORCE_DOMAIN, &required, sizeof (int));
    assert (rc == 0);
#endif
}

struct curve_client_data_t
{
    const char *server_public;
    const char *client_public;
    const char *client_secret;
};

void socket_config_curve_client (void *client_, void *data_)
{
    curve_client_data_t *curve_client_data =
      static_cast<curve_client_data_t *> (data_);

    int rc = zmq_setsockopt (client_, ZMQ_CURVE_SERVERKEY,
                             curve_client_data->server_public, 41);
    assert (rc == 0);
    rc = zmq_setsockopt (client_, ZMQ_CURVE_PUBLICKEY,
                         curve_client_data->client_public, 41);
    assert (rc == 0);
    rc = zmq_setsockopt (client_, ZMQ_CURVE_SECRETKEY,
                         curve_client_data->client_secret, 41);
    assert (rc == 0);
}

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
    zap_too_many_parts,
    zap_disconnect,
    zap_do_not_recv,
    zap_do_not_send
};

void *zap_requests_handled;

void zap_handler_generic (void *ctx_,
                          zap_protocol_t zap_protocol_,
                          const char *expected_routing_id_ = "IDENT")
{
    void *control = zmq_socket (ctx_, ZMQ_REQ);
    assert (control);
    int rc = zmq_connect (control, "inproc://handler-control");
    assert (rc == 0);

    void *handler = zmq_socket (ctx_, ZMQ_REP);
    assert (handler);
    rc = zmq_bind (handler, "inproc://zeromq.zap.01");
    assert (rc == 0);

    //  Signal main thread that we are ready
    rc = s_send (control, "GO");
    assert (rc == 2);

    zmq_pollitem_t items[] = {
      {control, 0, ZMQ_POLLIN, 0},
      {handler, 0, ZMQ_POLLIN, 0},
    };

    // if ordered not to receive the request, ignore the second poll item
    const int numitems = (zap_protocol_ == zap_do_not_recv) ? 1 : 2;

    //  Process ZAP requests forever
    while (zmq_poll (items, numitems, -1) >= 0) {
        if (items[0].revents & ZMQ_POLLIN) {
            char *buf = s_recv (control);
            assert (buf);
            assert (streq (buf, "STOP"));
            free (buf);
            break; //  Terminating - main thread signal
        }
        if (!(items[1].revents & ZMQ_POLLIN))
            continue;

        char *version = s_recv (handler);
        if (!version)
            break; //  Terminating - peer's socket closed
        if (zap_protocol_ == zap_disconnect) {
            free (version);
            break;
        }

        char *sequence = s_recv (handler);
        char *domain = s_recv (handler);
        char *address = s_recv (handler);
        char *routing_id = s_recv (handler);
        char *mechanism = s_recv (handler);
        bool authentication_succeeded = false;
        if (streq (mechanism, "CURVE")) {
            uint8_t client_key[32];
            int size = zmq_recv (handler, client_key, 32, 0);
            assert (size == 32);

            char client_key_text[41];
            zmq_z85_encode (client_key_text, client_key, 32);

            authentication_succeeded =
              streq (client_key_text, valid_client_public);
        } else if (streq (mechanism, "PLAIN")) {
            char client_username[32];
            int size = zmq_recv (handler, client_username, 32, 0);
            assert (size > 0);
            client_username[size] = 0;

            char client_password[32];
            size = zmq_recv (handler, client_password, 32, 0);
            assert (size > 0);
            client_password[size] = 0;

            authentication_succeeded =
              streq (test_plain_username, client_username)
              && streq (test_plain_password, client_password);
        } else if (streq (mechanism, "NULL")) {
            authentication_succeeded = true;
        } else {
            fprintf (stderr, "Unsupported mechanism: %s\n", mechanism);
            assert (false);
        }

        assert (streq (version, "1.0"));
        assert (streq (routing_id, expected_routing_id_));

        s_sendmore (handler, zap_protocol_ == zap_wrong_version
                               ? "invalid_version"
                               : version);
        s_sendmore (handler, zap_protocol_ == zap_wrong_request_id
                               ? "invalid_request_id"
                               : sequence);

        if (authentication_succeeded) {
            const char *status_code;
            switch (zap_protocol_) {
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
            if (zap_protocol_ == zap_too_many_parts) {
                s_sendmore (handler, "");
            }
            if (zap_protocol_ != zap_do_not_send)
                s_send (handler, "");
        } else {
            s_sendmore (handler, "400");
            s_sendmore (handler, "Invalid client public key");
            s_sendmore (handler, "");
            if (zap_protocol_ != zap_do_not_send)
                s_send (handler, "");
        }
        free (version);
        free (sequence);
        free (domain);
        free (address);
        free (routing_id);
        free (mechanism);

        zmq_atomic_counter_inc (zap_requests_handled);
    }
    rc = zmq_unbind (handler, "inproc://zeromq.zap.01");
    assert (rc == 0);
    close_zero_linger (handler);

    if (zap_protocol_ != zap_disconnect) {
        rc = s_send (control, "STOPPED");
        assert (rc == 7);
    }
    close_zero_linger (control);
}

void zap_handler (void *ctx_)
{
    zap_handler_generic (ctx_, zap_ok);
}

//  Monitor event utilities

//  Read one event off the monitor socket; return value and address
//  by reference, if not null, and event number by value. Returns -1
//  in case of error.

static int get_monitor_event_internal (void *monitor_,
                                       int *value_,
                                       char **address_,
                                       int recv_flag_)
{
    //  First frame in message contains event number and value
    zmq_msg_t msg;
    zmq_msg_init (&msg);
    if (zmq_msg_recv (&msg, monitor_, recv_flag_) == -1) {
        assert (errno == EAGAIN);
        return -1; //  timed out or no message available
    }
    assert (zmq_msg_more (&msg));

    uint8_t *data = (uint8_t *) zmq_msg_data (&msg);
    uint16_t event = *(uint16_t *) (data);
    if (value_)
        *value_ = *(uint32_t *) (data + 2);

    //  Second frame in message contains event address
    zmq_msg_init (&msg);
    int res = zmq_msg_recv (&msg, monitor_, recv_flag_) == -1;
    assert (res != -1);
    assert (!zmq_msg_more (&msg));

    if (address_) {
        uint8_t *data = (uint8_t *) zmq_msg_data (&msg);
        size_t size = zmq_msg_size (&msg);
        *address_ = (char *) malloc (size + 1);
        memcpy (*address_, data, size);
        *address_[size] = 0;
    }
    return event;
}

int get_monitor_event_with_timeout (void *monitor_,
                                    int *value_,
                                    char **address_,
                                    int timeout_)
{
    int res;
    if (timeout_ == -1) {
        // process infinite timeout in small steps to allow the user
        // to see some information on the console

        int timeout_step = 250;
        int wait_time = 0;
        zmq_setsockopt (monitor_, ZMQ_RCVTIMEO, &timeout_step,
                        sizeof (timeout_step));
        while (
          (res = get_monitor_event_internal (monitor_, value_, address_, 0))
          == -1) {
            wait_time += timeout_step;
            fprintf (stderr, "Still waiting for monitor event after %i ms\n",
                     wait_time);
        }
    } else {
        zmq_setsockopt (monitor_, ZMQ_RCVTIMEO, &timeout_, sizeof (timeout_));
        res = get_monitor_event_internal (monitor_, value_, address_, 0);
    }
    int timeout_infinite = -1;
    zmq_setsockopt (monitor_, ZMQ_RCVTIMEO, &timeout_infinite,
                    sizeof (timeout_infinite));
    return res;
}

int get_monitor_event (void *monitor_, int *value_, char **address_)
{
    return get_monitor_event_with_timeout (monitor_, value_, address_, -1);
}

void expect_monitor_event (void *monitor_, int expected_event_)
{
    int event = get_monitor_event (monitor_, NULL, NULL);
    if (event != expected_event_) {
        fprintf (stderr, "Expected monitor event %x but received %x\n",
                 expected_event_, event);
        assert (event == expected_event_);
    }
}

void print_unexpected_event (int event_,
                             int err_,
                             int expected_event_,
                             int expected_err_)
{
    fprintf (stderr,
             "Unexpected event: 0x%x, value = %i/0x%x (expected: 0x%x, value "
             "= %i/0x%x)\n",
             event_, err_, err_, expected_event_, expected_err_, expected_err_);
}

//  expects that one or more occurrences of the expected event are received
//  via the specified socket monitor
//  returns the number of occurrences of the expected event
//  interrupts, if a ZMQ_EVENT_HANDSHAKE_FAILED_NO_DETAIL with EPIPE, ECONNRESET
//  or ECONNABORTED occurs; in this case, 0 is returned
//  this should be investigated further, see
//  https://github.com/zeromq/libzmq/issues/2644
int expect_monitor_event_multiple (void *server_mon_,
                                   int expected_event_,
                                   int expected_err_ = -1,
                                   bool optional_ = false)
{
    int count_of_expected_events = 0;
    int client_closed_connection = 0;
    int timeout = 250;
    int wait_time = 0;

    int event;
    int err;
    while ((event =
              get_monitor_event_with_timeout (server_mon_, &err, NULL, timeout))
             != -1
           || !count_of_expected_events) {
        if (event == -1) {
            if (optional_)
                break;
            wait_time += timeout;
            fprintf (stderr,
                     "Still waiting for first event after %ims (expected event "
                     "%x (value %i/0x%x))\n",
                     wait_time, expected_event_, expected_err_, expected_err_);
            continue;
        }
        // ignore errors with EPIPE/ECONNRESET/ECONNABORTED, which can happen
        // ECONNRESET can happen on very slow machines, when the engine writes
        // to the peer and then tries to read the socket before the peer reads
        // ECONNABORTED happens when a client aborts a connection via RST/timeout
        if (event == ZMQ_EVENT_HANDSHAKE_FAILED_NO_DETAIL
            && ((err == EPIPE && expected_err_ != EPIPE) || err == ECONNRESET
                || err == ECONNABORTED)) {
            fprintf (stderr,
                     "Ignored event (skipping any further events): %x (err = "
                     "%i == %s)\n",
                     event, err, zmq_strerror (err));
            client_closed_connection = 1;
            break;
        }
        if (event != expected_event_
            || (-1 != expected_err_ && err != expected_err_)) {
            print_unexpected_event (event, err, expected_event_, expected_err_);
            assert (false);
        }
        ++count_of_expected_events;
    }
    assert (optional_ || count_of_expected_events > 0
            || client_closed_connection);

    return count_of_expected_events;
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
            if (event == ZMQ_EVENT_HANDSHAKE_FAILED_NO_DETAIL                  \
                && (err == EPIPE || err == ECONNRESET                          \
                    || err == ECONNABORTED)) {                                 \
                fprintf (stderr,                                               \
                         "Ignored event (skipping any further events): %x "    \
                         "(err = %i == %s)\n",                                 \
                         event, err, zmq_strerror (err));                      \
                continue;                                                      \
            }                                                                  \
            ++event_count;                                                     \
            print_unexpected_event (event, err, 0, 0);                         \
        }                                                                      \
        assert (event_count == 0);                                             \
    }

void setup_handshake_socket_monitor (void *ctx_,
                                     void *server_,
                                     void **server_mon_,
                                     const char *monitor_endpoint_)
{
    //  Monitor handshake events on the server
    int rc = zmq_socket_monitor (server_, monitor_endpoint_,
                                 ZMQ_EVENT_HANDSHAKE_SUCCEEDED
                                   | ZMQ_EVENT_HANDSHAKE_FAILED_NO_DETAIL
                                   | ZMQ_EVENT_HANDSHAKE_FAILED_AUTH
                                   | ZMQ_EVENT_HANDSHAKE_FAILED_PROTOCOL);
    assert (rc == 0);

    //  Create socket for collecting monitor events
    *server_mon_ = zmq_socket (ctx_, ZMQ_PAIR);
    assert (*server_mon_);
    int linger = 0;
    rc = zmq_setsockopt (*server_mon_, ZMQ_LINGER, &linger, sizeof (linger));
    assert (rc == 0);

    //  Connect it to the inproc endpoints so they'll get events
    rc = zmq_connect (*server_mon_, monitor_endpoint_);
    assert (rc == 0);
}

void setup_context_and_server_side (
  void **ctx_,
  void **zap_control_,
  void **zap_thread_,
  void **server_,
  void **server_mon_,
  char *my_endpoint_,
  zmq_thread_fn zap_handler_ = &zap_handler,
  socket_config_fn socket_config_ = &socket_config_curve_server,
  void *socket_config_data_ = valid_server_secret,
  const char *routing_id_ = "IDENT")
{
    *ctx_ = zmq_ctx_new ();
    assert (*ctx_);

    //  Spawn ZAP handler
    zap_requests_handled = zmq_atomic_counter_new ();
    assert (zap_requests_handled != NULL);

    *zap_control_ = zmq_socket (*ctx_, ZMQ_REP);
    assert (*zap_control_);
    int rc = zmq_bind (*zap_control_, "inproc://handler-control");
    assert (rc == 0);
    int linger = 0;
    rc = zmq_setsockopt (*zap_control_, ZMQ_LINGER, &linger, sizeof (linger));
    assert (rc == 0);

    if (zap_handler_ != NULL) {
        *zap_thread_ = zmq_threadstart (zap_handler_, *ctx_);

        char *buf = s_recv (*zap_control_);
        assert (buf);
        assert (streq (buf, "GO"));
        free (buf);
    } else
        *zap_thread_ = NULL;

    //  Server socket will accept connections
    *server_ = zmq_socket (*ctx_, ZMQ_DEALER);
    assert (*server_);
    rc = zmq_setsockopt (*server_, ZMQ_LINGER, &linger, sizeof (linger));
    assert (rc == 0);

    socket_config_ (*server_, socket_config_data_);

    rc = zmq_setsockopt (*server_, ZMQ_ROUTING_ID, routing_id_,
                         strlen (routing_id_));
    assert (rc == 0);

    rc = zmq_bind (*server_, "tcp://127.0.0.1:*");
    assert (rc == 0);

    size_t len = MAX_SOCKET_STRING;
    rc = zmq_getsockopt (*server_, ZMQ_LAST_ENDPOINT, my_endpoint_, &len);
    assert (rc == 0);

    const char server_monitor_endpoint[] = "inproc://monitor-server";
    setup_handshake_socket_monitor (*ctx_, *server_, server_mon_,
                                    server_monitor_endpoint);
}

void shutdown_context_and_server_side (void *ctx_,
                                       void *zap_thread_,
                                       void *server_,
                                       void *server_mon_,
                                       void *zap_control_,
                                       bool zap_handler_stopped_ = false)
{
    if (zap_thread_ && !zap_handler_stopped_) {
        int rc = s_send (zap_control_, "STOP");
        assert (rc == 4);
        char *buf = s_recv (zap_control_);
        assert (buf);
        assert (streq (buf, "STOPPED"));
        free (buf);
        rc = zmq_unbind (zap_control_, "inproc://handler-control");
        assert (rc == 0);
    }
    int rc = zmq_close (zap_control_);
    assert (rc == 0);

    rc = zmq_close (server_mon_);
    assert (rc == 0);
    rc = zmq_close (server_);
    assert (rc == 0);

    //  Wait until ZAP handler terminates
    if (zap_thread_)
        zmq_threadclose (zap_thread_);

    rc = zmq_ctx_term (ctx_);
    assert (rc == 0);

    zmq_atomic_counter_destroy (&zap_requests_handled);
}

void *create_and_connect_client (void *ctx_,
                                 char *my_endpoint_,
                                 socket_config_fn socket_config_,
                                 void *socket_config_data_,
                                 void **client_mon_ = NULL)
{
    void *client = zmq_socket (ctx_, ZMQ_DEALER);
    assert (client);

    socket_config_ (client, socket_config_data_);

    int rc = zmq_connect (client, my_endpoint_);
    assert (rc == 0);

    if (client_mon_) {
        setup_handshake_socket_monitor (ctx_, client, client_mon_,
                                        "inproc://client-monitor");
    }

    return client;
}

void expect_new_client_bounce_fail (void *ctx_,
                                    char *my_endpoint_,
                                    void *server_,
                                    socket_config_fn socket_config_,
                                    void *socket_config_data_,
                                    void **client_mon_ = NULL,
                                    int expected_client_event_ = 0,
                                    int expected_client_value_ = 0)
{
    void *my_client_mon;
    assert (client_mon_ == NULL || expected_client_event_ == 0);
    if (expected_client_event_ != 0)
        client_mon_ = &my_client_mon;
    void *client = create_and_connect_client (
      ctx_, my_endpoint_, socket_config_, socket_config_data_, client_mon_);
    expect_bounce_fail (server_, client);

    if (expected_client_event_ != 0) {
        int events_received = 0;
        events_received = expect_monitor_event_multiple (
          my_client_mon, expected_client_event_, expected_client_value_, false);

        assert (events_received == 1);

        int rc = zmq_close (my_client_mon);
        assert (rc == 0);
    }

    close_zero_linger (client);
}

#endif
