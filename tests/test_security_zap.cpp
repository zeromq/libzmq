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

#include "testutil_security.hpp"
#include "testutil_unity.hpp"

SETUP_TEARDOWN_TESTCONTEXT

static void zap_handler_wrong_version (void * /*unused_*/)
{
    zap_handler_generic (zap_wrong_version);
}

static void zap_handler_wrong_request_id (void * /*unused_*/)
{
    zap_handler_generic (zap_wrong_request_id);
}

static void zap_handler_wrong_status_invalid (void * /*unused_*/)
{
    zap_handler_generic (zap_status_invalid);
}

static void zap_handler_wrong_status_temporary_failure (void * /*unused_*/)
{
    zap_handler_generic (zap_status_temporary_failure);
}

static void zap_handler_wrong_status_internal_error (void * /*unused_*/)
{
    zap_handler_generic (zap_status_internal_error);
}

static void zap_handler_too_many_parts (void * /*unused_*/)
{
    zap_handler_generic (zap_too_many_parts);
}

static void zap_handler_disconnect (void * /*unused_*/)
{
    zap_handler_generic (zap_disconnect);
}

static void zap_handler_do_not_recv (void * /*unused_*/)
{
    zap_handler_generic (zap_do_not_recv);
}

static void zap_handler_do_not_send (void * /*unused_*/)
{
    zap_handler_generic (zap_do_not_send);
}

int expect_new_client_bounce_fail_and_count_monitor_events (
  char *my_endpoint_,
  void *server_,
  socket_config_fn socket_config_,
  void *socket_config_data_,
  void **client_mon_,
  void *server_mon_,
  int expected_server_event_,
  int expected_server_value_,
  int expected_client_event_ = 0,
  int expected_client_value_ = 0)
{
    expect_new_client_bounce_fail (
      my_endpoint_, server_, socket_config_, socket_config_data_, client_mon_,
      expected_client_event_, expected_client_value_);

    int events_received = 0;
    events_received = expect_monitor_event_multiple (
      server_mon_, expected_server_event_, expected_server_value_);

    return events_received;
}

void test_zap_unsuccessful (char *my_endpoint_,
                            void *server_,
                            void *server_mon_,
                            int expected_server_event_,
                            int expected_server_value_,
                            socket_config_fn socket_config_,
                            void *socket_config_data_,
                            void **client_mon_ = NULL,
                            int expected_client_event_ = 0,
                            int expected_client_value_ = 0)
{
    int server_events_received =
      expect_new_client_bounce_fail_and_count_monitor_events (
        my_endpoint_, server_, socket_config_, socket_config_data_, client_mon_,
        server_mon_, expected_server_event_, expected_server_value_,
        expected_client_event_, expected_client_value_);

    //  there may be more than one ZAP request due to repeated attempts by the
    //  client (actually only in case if ZAP status code 300)
    TEST_ASSERT_TRUE (server_events_received == 0
                      || 1 <= zmq_atomic_counter_value (zap_requests_handled));
}

void test_zap_unsuccessful_no_handler (char *my_endpoint_,
                                       void *server_,
                                       void *server_mon_,
                                       int expected_event_,
                                       int expected_err_,
                                       socket_config_fn socket_config_,
                                       void *socket_config_data_,
                                       void **client_mon_ = NULL)
{
    const int events_received =
      expect_new_client_bounce_fail_and_count_monitor_events (
        my_endpoint_, server_, socket_config_, socket_config_data_, client_mon_,
        server_mon_, expected_event_, expected_err_);

    //  there may be more than one ZAP request due to repeated attempts by the
    //  client
    TEST_ASSERT_GREATER_THAN_INT (0, events_received);
}

void test_zap_protocol_error (char *my_endpoint_,
                              void *server_,
                              void *server_mon_,
                              socket_config_fn socket_config_,
                              void *socket_config_data_,
                              int expected_error_)
{
    test_zap_unsuccessful (my_endpoint_, server_, server_mon_,
                           ZMQ_EVENT_HANDSHAKE_FAILED_PROTOCOL, expected_error_,
                           socket_config_, socket_config_data_);
}

void test_zap_unsuccessful_status_300 (char *my_endpoint_,
                                       void *server_,
                                       void *server_mon_,
                                       socket_config_fn client_socket_config_,
                                       void *client_socket_config_data_)
{
    void *client_mon;
    test_zap_unsuccessful (
      my_endpoint_, server_, server_mon_, ZMQ_EVENT_HANDSHAKE_FAILED_AUTH, 300,
      client_socket_config_, client_socket_config_data_, &client_mon);

    // we can use a 0 timeout here, since the client socket is already closed
    assert_no_more_monitor_events_with_timeout (client_mon, 0);

    test_context_socket_close (client_mon);
}

void test_zap_unsuccessful_status_500 (char *my_endpoint_,
                                       void *server_,
                                       void *server_mon_,
                                       socket_config_fn client_socket_config_,
                                       void *client_socket_config_data_)
{
    test_zap_unsuccessful (my_endpoint_, server_, server_mon_,
                           ZMQ_EVENT_HANDSHAKE_FAILED_AUTH, 500,
                           client_socket_config_, client_socket_config_data_,
                           NULL, ZMQ_EVENT_HANDSHAKE_FAILED_AUTH, 500);
}

static void
test_zap_protocol_error_closure (socket_config_fn server_socket_config_,
                                 socket_config_fn client_socket_config_,
                                 void *client_socket_config_data_,
                                 void *server_socket_config_data_,
                                 zmq_thread_fn zap_handler_,
                                 int expected_failure_)
{
    void *handler, *zap_thread, *server, *server_mon;
    char my_endpoint[MAX_SOCKET_STRING];

    setup_context_and_server_side (
      &handler, &zap_thread, &server, &server_mon, my_endpoint, zap_handler_,
      server_socket_config_, server_socket_config_data_);
    test_zap_protocol_error (my_endpoint, server, server_mon,
                             client_socket_config_, client_socket_config_data_,
                             expected_failure_);
    shutdown_context_and_server_side (zap_thread, server, server_mon, handler);
}

static void
test_zap_protocol_error_wrong_version (socket_config_fn server_socket_config_,
                                       socket_config_fn client_socket_config_,
                                       void *client_socket_config_data_,
                                       void *server_socket_config_data_)
{
    test_zap_protocol_error_closure (
      server_socket_config_, client_socket_config_, client_socket_config_data_,
      server_socket_config_data_, &zap_handler_wrong_version,
      ZMQ_PROTOCOL_ERROR_ZAP_BAD_VERSION);
}

static void test_zap_protocol_error_wrong_request_id (
  socket_config_fn server_socket_config_,
  socket_config_fn client_socket_config_,
  void *client_socket_config_data_,
  void *server_socket_config_data_)
{
    test_zap_protocol_error_closure (
      server_socket_config_, client_socket_config_, client_socket_config_data_,
      server_socket_config_data_, &zap_handler_wrong_request_id,
      ZMQ_PROTOCOL_ERROR_ZAP_BAD_REQUEST_ID);
}

static void test_zap_protocol_error_wrong_status_invalid (
  socket_config_fn server_socket_config_,
  socket_config_fn client_socket_config_,
  void *client_socket_config_data_,
  void *server_socket_config_data_)
{
    test_zap_protocol_error_closure (
      server_socket_config_, client_socket_config_, client_socket_config_data_,
      server_socket_config_data_, &zap_handler_wrong_status_invalid,
      ZMQ_PROTOCOL_ERROR_ZAP_INVALID_STATUS_CODE);
}

static void
test_zap_protocol_error_too_many_parts (socket_config_fn server_socket_config_,
                                        socket_config_fn client_socket_config_,
                                        void *client_socket_config_data_,
                                        void *server_socket_config_data_)
{
    test_zap_protocol_error_closure (
      server_socket_config_, client_socket_config_, client_socket_config_data_,
      server_socket_config_data_, &zap_handler_too_many_parts,
      ZMQ_PROTOCOL_ERROR_ZAP_MALFORMED_REPLY);
}

//  TODO the failed status (300/500) should be observable as monitoring events on the client side as well (they are
//  already transmitted as an ERROR message)

static void
test_zap_wrong_status_temporary_failure (socket_config_fn server_socket_config_,
                                         socket_config_fn client_socket_config_,
                                         void *client_socket_config_data_,
                                         void *server_socket_config_data_)
{
    void *handler, *zap_thread, *server, *server_mon;
    char my_endpoint[MAX_SOCKET_STRING];
    setup_context_and_server_side (
      &handler, &zap_thread, &server, &server_mon, my_endpoint,
      &zap_handler_wrong_status_temporary_failure, server_socket_config_,
      server_socket_config_data_);
    test_zap_unsuccessful_status_300 (my_endpoint, server, server_mon,
                                      client_socket_config_,
                                      client_socket_config_data_);
    shutdown_context_and_server_side (zap_thread, server, server_mon, handler);
}

static void
test_zap_wrong_status_internal_error (socket_config_fn server_socket_config_,
                                      socket_config_fn client_socket_config_,
                                      void *client_socket_config_data_)
{
    void *handler, *zap_thread, *server, *server_mon;
    char my_endpoint[MAX_SOCKET_STRING];
    setup_context_and_server_side (
      &handler, &zap_thread, &server, &server_mon, my_endpoint,
      &zap_handler_wrong_status_internal_error, server_socket_config_);
    test_zap_unsuccessful_status_500 (my_endpoint, server, server_mon,
                                      client_socket_config_,
                                      client_socket_config_data_);
    shutdown_context_and_server_side (zap_thread, server, server_mon, handler);
}

static void
test_zap_unsuccesful_no_handler_started (socket_config_fn server_socket_config_,
                                         socket_config_fn client_socket_config_,
                                         void *client_socket_config_data_,
                                         void *server_socket_config_data_)
{
#ifdef ZMQ_ZAP_ENFORCE_DOMAIN
    void *handler, *zap_thread, *server, *server_mon;
    char my_endpoint[MAX_SOCKET_STRING];
    // TODO this looks wrong, where will the enforce value be used?

    //  no ZAP handler
    int enforce = 1;
    setup_context_and_server_side (
      &handler, &zap_thread, &server, &server_mon, my_endpoint, NULL,
      server_socket_config_,
      server_socket_config_data_ ? server_socket_config_data_ : &enforce);
    test_zap_unsuccessful_no_handler (
      my_endpoint, server, server_mon, ZMQ_EVENT_HANDSHAKE_FAILED_NO_DETAIL,
      EFAULT, client_socket_config_, client_socket_config_data_);
    shutdown_context_and_server_side (zap_thread, server, server_mon, handler);
#endif
}

static void
test_zap_unsuccesful_no_handler_closure (socket_config_fn server_socket_config_,
                                         socket_config_fn client_socket_config_,
                                         void *client_socket_config_data_,
                                         zmq_thread_fn zap_handler_func_,
                                         bool zap_handler_disconnected_ = false)
{
    void *handler, *zap_thread, *server, *server_mon;
    char my_endpoint[MAX_SOCKET_STRING];
    setup_context_and_server_side (&handler, &zap_thread, &server, &server_mon,
                                   my_endpoint, zap_handler_func_,
                                   server_socket_config_);
    test_zap_unsuccessful_no_handler (
      my_endpoint, server, server_mon, ZMQ_EVENT_HANDSHAKE_FAILED_NO_DETAIL,
      EPIPE, client_socket_config_, client_socket_config_data_);
    shutdown_context_and_server_side (zap_thread, server, server_mon, handler,
                                      zap_handler_disconnected_);
}

static void
test_zap_unsuccesful_disconnect (socket_config_fn server_socket_config_,
                                 socket_config_fn client_socket_config_,
                                 void *client_socket_config_data_)
{
    test_zap_unsuccesful_no_handler_closure (
      server_socket_config_, client_socket_config_, client_socket_config_data_,
      &zap_handler_disconnect, true);
}

static void
test_zap_unsuccesful_do_not_recv (socket_config_fn server_socket_config_,
                                  socket_config_fn client_socket_config_,
                                  void *client_socket_config_data_)
{
    test_zap_unsuccesful_no_handler_closure (
      server_socket_config_, client_socket_config_, client_socket_config_data_,
      &zap_handler_do_not_recv);
}

static void
test_zap_unsuccesful_do_not_send (socket_config_fn server_socket_config_,
                                  socket_config_fn client_socket_config_,
                                  void *client_socket_config_data_)
{
    test_zap_unsuccesful_no_handler_closure (
      server_socket_config_, client_socket_config_, client_socket_config_data_,
      &zap_handler_do_not_send);
}

#define DEFINE_ZAP_ERROR_TESTS(                                                \
  name_, server_socket_config_, server_socket_config_data_,                    \
  client_socket_config_, client_socket_config_data_)                           \
    void test_zap_protocol_error_wrong_version_##name_ ()                      \
    {                                                                          \
        test_zap_protocol_error_wrong_version (                                \
          server_socket_config_, client_socket_config_,                        \
          client_socket_config_data_, server_socket_config_data_);             \
    }                                                                          \
    void test_zap_protocol_error_wrong_request_id_##name_ ()                   \
    {                                                                          \
        test_zap_protocol_error_wrong_request_id (                             \
          server_socket_config_, client_socket_config_,                        \
          client_socket_config_data_, server_socket_config_data_);             \
    }                                                                          \
    void test_zap_protocol_error_wrong_status_invalid_##name_ ()               \
    {                                                                          \
        test_zap_protocol_error_wrong_status_invalid (                         \
          server_socket_config_, client_socket_config_,                        \
          client_socket_config_data_, server_socket_config_data_);             \
    }                                                                          \
    void test_zap_protocol_error_too_many_parts_##name_ ()                     \
    {                                                                          \
        test_zap_protocol_error_too_many_parts (                               \
          server_socket_config_, client_socket_config_,                        \
          client_socket_config_data_, server_socket_config_data_);             \
    }                                                                          \
    void test_zap_wrong_status_temporary_failure_##name_ ()                    \
    {                                                                          \
        test_zap_wrong_status_temporary_failure (                              \
          server_socket_config_, client_socket_config_,                        \
          client_socket_config_data_, server_socket_config_data_);             \
    }                                                                          \
    void test_zap_wrong_status_internal_error_##name_ ()                       \
    {                                                                          \
        test_zap_wrong_status_internal_error (server_socket_config_,           \
                                              client_socket_config_,           \
                                              client_socket_config_data_);     \
    }                                                                          \
    void test_zap_unsuccessful_no_handler_started_##name_ ()                   \
    {                                                                          \
        test_zap_unsuccesful_no_handler_started (                              \
          server_socket_config_, client_socket_config_,                        \
          client_socket_config_data_, server_socket_config_data_);             \
    }                                                                          \
    void test_zap_unsuccessful_disconnect_##name_ ()                           \
    {                                                                          \
        test_zap_unsuccesful_disconnect (server_socket_config_,                \
                                         client_socket_config_,                \
                                         client_socket_config_data_);          \
    }                                                                          \
    void test_zap_unsuccessful_do_not_recv_##name_ ()                          \
    {                                                                          \
        test_zap_unsuccesful_do_not_recv (server_socket_config_,               \
                                          client_socket_config_,               \
                                          client_socket_config_data_);         \
    }                                                                          \
    void test_zap_unsuccessful_do_not_send_##name_ ()                          \
    {                                                                          \
        test_zap_unsuccesful_do_not_send (server_socket_config_,               \
                                          client_socket_config_,               \
                                          client_socket_config_data_);         \
    }

DEFINE_ZAP_ERROR_TESTS (
  null, &socket_config_null_server, NULL, &socket_config_null_client, NULL)

DEFINE_ZAP_ERROR_TESTS (
  plain, &socket_config_plain_server, NULL, &socket_config_plain_client, NULL)

static curve_client_data_t curve_client_data = {
  valid_server_public, valid_client_public, valid_client_secret};

DEFINE_ZAP_ERROR_TESTS (curve,
                        &socket_config_curve_server,
                        valid_server_secret,
                        &socket_config_curve_client,
                        &curve_client_data)

#define RUN_ZAP_ERROR_TESTS(name_)                                             \
    {                                                                          \
        RUN_TEST (test_zap_protocol_error_wrong_version_##name_);              \
        RUN_TEST (test_zap_protocol_error_wrong_request_id_##name_);           \
        RUN_TEST (test_zap_protocol_error_wrong_status_invalid_##name_);       \
        RUN_TEST (test_zap_protocol_error_too_many_parts_##name_);             \
        RUN_TEST (test_zap_wrong_status_temporary_failure_##name_);            \
        RUN_TEST (test_zap_wrong_status_internal_error_##name_);               \
        RUN_TEST (test_zap_unsuccessful_no_handler_started_##name_);           \
        RUN_TEST (test_zap_unsuccessful_disconnect_##name_);                   \
        RUN_TEST (test_zap_unsuccessful_do_not_recv_##name_);                  \
        RUN_TEST (test_zap_unsuccessful_do_not_send_##name_);                  \
    }

int main ()
{
    setup_test_environment ();

    if (zmq_has ("curve")) {
        setup_testutil_security_curve ();
    }

    UNITY_BEGIN ();
    RUN_ZAP_ERROR_TESTS (null);
    RUN_ZAP_ERROR_TESTS (plain);
    if (zmq_has ("curve")) {
        RUN_ZAP_ERROR_TESTS (curve);
    }
    return UNITY_END ();
}
