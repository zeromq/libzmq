/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_security.hpp"

#include "testutil_unity.hpp"

#include <stdlib.h>
#include <string.h>

SETUP_TEARDOWN_TESTCONTEXT

//  These tests cover the endpoint lifecycle after a protocol error.
//
//  Background: a protocol error tears a session down for good - we do not
//  reconnect to a peer that speaks a bad protocol. The connecting socket must
//  therefore also drop the endpoint from socket_base_t::_endpoints. If it does
//  not, the stale entry is a "zombie": the single-connect guard in
//  connect_internal() still counts it, so every later zmq_connect() to the same
//  URI on SUB/PUB/DEALER/REQ silently returns 0 and does nothing, and the socket
//  can never reestablish a connection to that endpoint in the future.
//
//  The de-registration request identifies the connection by its owning object
//  rather than by URI, for two reasons the tests below pin down:
//    * the key in _endpoints is the raw string the user passed to zmq_connect(),
//      but the I/O thread only knows the *resolved* address, so a connection
//      made via a hostname would never match; and
//    * _endpoints is a multimap, so erasing by URI would tear down *every*
//      connection sharing that URI when only one of them had failed.

#define SHORT_SETTLE_TIME 100 //ms

//  Reconnection is disabled outright so that a revived connection can never mask
//  a result. A protocol error already suppresses reconnect, but the sibling
//  connection in the aliasing test is torn down by a *different* path.
static const int no_reconnect = -1;

//  Message length comfortably over the ZMQ_MAXMSGSIZE the clients below set.
#define OVERSIZED_LEN 4000
static const int64_t max_msg_size = 1000;

//  Provoke a post-handshake protocol error on the peer of server_ by sending a
//  frame larger than its ZMQ_MAXMSGSIZE, which its decoder rejects with
//  EMSGSIZE. Sent a few times with ZMQ_DONTWAIT (the pipe dies on the first one)
//  so a lost race still triggers it, then allowed to settle.
static void trigger_protocol_error (void *server_)
{
    char big_msg[OVERSIZED_LEN];
    memset (big_msg, 'x', sizeof big_msg);
    for (int i = 0; i < 3; ++i) {
        zmq_send (server_, big_msg, sizeof big_msg, ZMQ_DONTWAIT);
        msleep (10);
    }
    msleep (SETTLE_TIME);
}

//  Bring up a bound server and a connecting client with a small ZMQ_MAXMSGSIZE,
//  handshaked and carrying data. The client is the connecting side, so it is the
//  one that owns an _endpoints entry and whose decoder rejects the bad frame.
//  Returns the server's endpoint through endpoint_out_.
static void setup_pipe (void **server_,
                        void **client_,
                        int server_type_,
                        int client_type_,
                        char *endpoint_out_,
                        size_t endpoint_out_len_)
{
    *server_ = test_context_socket (server_type_);
    bind_loopback_ipv4 (*server_, endpoint_out_, endpoint_out_len_);

    *client_ = test_context_socket (client_type_);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      *client_, ZMQ_MAXMSGSIZE, &max_msg_size, sizeof max_msg_size));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      *client_, ZMQ_RECONNECT_IVL, &no_reconnect, sizeof no_reconnect));
    if (client_type_ == ZMQ_SUB) {
        TEST_ASSERT_SUCCESS_ERRNO (
          zmq_setsockopt (*client_, ZMQ_SUBSCRIBE, "", 0));
    }

    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (*client_, endpoint_out_));
    msleep (SHORT_SETTLE_TIME);

    //  One in-limit message, so the error that follows is unambiguously
    //  post-handshake.
    send_string_expect_success (*server_, "in-limit", 0);
    recv_string_expect_success (*client_, "in-limit", 0);
}

//  ---------------------------------------------------------------------------
//  The aliasing issue repro.
//
//  A PULL socket is not subject to the single-connect guard, so it may hold
//  several connections to one URI -- several _endpoints entries under one key.
//  A protocol error on one of them must take down that one only.
//
//  Erasing by URI uses multimap::equal_range() and so would remove *both*
//  entries, terminating the healthy sibling along with the failed one and
//  leaving the socket with no connection at all, so prior to patching, none of
//  the 20 messages below would arrive.
void test_sibling_connection_survives_protocol_error ()
{
    char endpoint[MAX_SOCKET_STRING];

    void *server = test_context_socket (ZMQ_PUSH);
    bind_loopback_ipv4 (server, endpoint, sizeof endpoint);

    void *client = test_context_socket (ZMQ_PULL);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      client, ZMQ_MAXMSGSIZE, &max_msg_size, sizeof max_msg_size));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      client, ZMQ_RECONNECT_IVL, &no_reconnect, sizeof no_reconnect));

    //  Two connections, one URI, hence two _endpoints entries sharing a key.
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (client, endpoint));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (client, endpoint));
    msleep (SETTLE_TIME);

    //  Confirm both are live: PUSH round-robins, so two messages exercise both
    //  pipes. (Receipt order is not guaranteed to alternate; we only care that
    //  two arrive.)
    send_string_expect_success (server, "a", 0);
    send_string_expect_success (server, "b", 0);
    recv_string_expect_success (client, "a", 0);
    recv_string_expect_success (client, "b", 0);

    //  Kill exactly one of the two connections with an oversized frame. Which of
    //  the two receives it is decided by PUSH's round-robin and does not matter.
    //
    //  Exactly one frame, deliberately: the retry loop that makes
    //  trigger_protocol_error() robust elsewhere would round-robin onto the
    //  second pipe and kill that one too. With two live pipes the send cannot
    //  fail, so one attempt is enough.
    char big_msg[OVERSIZED_LEN];
    memset (big_msg, 'x', sizeof big_msg);
    TEST_ASSERT_EQUAL_INT (
      OVERSIZED_LEN, zmq_send (server, big_msg, sizeof big_msg, ZMQ_DONTWAIT));
    msleep (SETTLE_TIME);

    //  The surviving connection must still deliver. PUSH now has one live pipe;
    //  every message goes down it.
    const int expected = 20;
    int received = 0;
    for (int i = 0; i < expected; ++i) {
        char buf[16];
        if (zmq_send (server, "msg", 3, ZMQ_DONTWAIT) != 3)
            break;
        //  Poll briefly: the send is asynchronous.
        for (int attempt = 0; attempt < 20; ++attempt) {
            if (zmq_recv (client, buf, sizeof buf, ZMQ_DONTWAIT) == 3) {
                ++received;
                break;
            }
            msleep (10);
        }
    }
    TEST_ASSERT_EQUAL_INT (expected, received);

    test_context_socket_close_zero_linger (server);
    test_context_socket_close_zero_linger (client);
}

//  ---------------------------------------------------------------------------
//  The most direct statement of the contract: once a protocol error has torn the
//  connection down, the endpoint really is gone, so the user's own
//  zmq_disconnect() for it must report ENOENT rather than silently succeeding.
//
//  This is the easy case: a single connection to a numeric address, where the
//  stored key and the resolved address happen to be the same string. It is here
//  as the baseline that the harder cases below vary from, by changing the
//  spelling of the URI or adding a second connection under it.
void test_endpoint_deregistered_after_protocol_error ()
{
    char endpoint[MAX_SOCKET_STRING];
    void *server, *client;
    setup_pipe (&server, &client, ZMQ_PUSH, ZMQ_PULL, endpoint,
                sizeof endpoint);

    trigger_protocol_error (server);

    TEST_ASSERT_FAILURE_ERRNO (ENOENT, zmq_disconnect (client, endpoint));

    test_context_socket_close_zero_linger (server);
    test_context_socket_close_zero_linger (client);
}

//  ---------------------------------------------------------------------------
//  The resolution-mismatch repro.
//
//  _endpoints is keyed on the raw string passed to zmq_connect(), but for TCP
//  the address is resolved later, on the I/O thread. A teardown request carrying
//  the resolved address ("tcp://127.0.0.1:P") could never match an entry stored
//  under a hostname ("tcp://localhost:P"), so the endpoint would be left behind.
//  SUB is single-connect, so the subsequent zmq_connect() would then be a silent
//  no-op and nothing would ever be delivered again.
//
//  This is the common case in practice: most real deployments connect by name.
void test_reconnect_after_protocol_error_via_hostname ()
{
    char bound_endpoint[MAX_SOCKET_STRING];

    void *server = test_context_socket (ZMQ_PUB);
    bind_loopback_ipv4 (server, bound_endpoint, sizeof bound_endpoint);

    //  Re-spell the bound endpoint via the "localhost" alias.
    const char *port = strrchr (bound_endpoint, ':');
    TEST_ASSERT_NOT_NULL (port);
    char host_endpoint[MAX_SOCKET_STRING];
    snprintf (host_endpoint, sizeof host_endpoint, "tcp://localhost%s", port);

    void *client = test_context_socket (ZMQ_SUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      client, ZMQ_MAXMSGSIZE, &max_msg_size, sizeof max_msg_size));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      client, ZMQ_RECONNECT_IVL, &no_reconnect, sizeof no_reconnect));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (client, ZMQ_SUBSCRIBE, "", 0));

    if (zmq_connect (client, host_endpoint) == -1) {
        test_context_socket_close_zero_linger (server);
        test_context_socket_close_zero_linger (client);
        TEST_IGNORE_MESSAGE ("'localhost' does not resolve here");
    }
    msleep (SETTLE_TIME);

    //  Confirm the hostname spelling actually reached the loopback listener
    //  before relying on it; skip rather than fail if the host resolves
    //  "localhost" somewhere else (or only to ::1).
    char buf[64];
    int rc = -1;
    for (int i = 0; i < 20 && rc < 0; ++i) {
        zmq_send (server, "in-limit", 8, ZMQ_DONTWAIT);
        msleep (10);
        rc = zmq_recv (client, buf, sizeof buf, ZMQ_DONTWAIT);
    }
    if (rc < 0) {
        test_context_socket_close_zero_linger (server);
        test_context_socket_close_zero_linger (client);
        TEST_IGNORE_MESSAGE (
          "'localhost' does not resolve to the IPv4 loopback");
    }

    trigger_protocol_error (server);

    //  The endpoint must be gone despite having been stored under a name the
    //  I/O thread never saw, so this connect creates a real connection rather
    //  than being swallowed by the single-connect guard.
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (client, host_endpoint));
    msleep (SETTLE_TIME);

    rc = -1;
    for (int i = 0; i < 30 && rc < 0; ++i) {
        zmq_send (server, "ok", 2, ZMQ_DONTWAIT);
        msleep (10);
        rc = zmq_recv (client, buf, sizeof buf, ZMQ_DONTWAIT);
    }
    TEST_ASSERT_EQUAL_INT (2, rc);

    test_context_socket_close_zero_linger (server);
    test_context_socket_close_zero_linger (client);
}

//  ---------------------------------------------------------------------------
//  Reconnect to the same endpoint after a protocol error and verify that data
//  flows again. With a zombie entry left behind, the single-connect guard turns
//  the second zmq_connect() into a silent no-op and nothing is ever delivered.
//
//  SUB and DEALER are single-connect, so the zombie is fatal on those; PULL is
//  not, so there the reconnect succeeds either way and only the teardown itself
//  is under test. The endpoint is spelled numerically, so this is purely the
//  lifecycle and not the resolution question the hostname test above covers.
//
//  ZMQ_PAIR is deliberately absent: it is an exclusive 1:1 socket that does not
//  re-establish a peer after disconnect, so reconnect-and-receive does not apply.
static void test_reconnect_after_protocol_error (int server_type_,
                                                 int client_type_)
{
    char endpoint[MAX_SOCKET_STRING];
    void *server, *client;
    setup_pipe (&server, &client, server_type_, client_type_, endpoint,
                sizeof endpoint);

    trigger_protocol_error (server);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (client, endpoint));
    msleep (SETTLE_TIME);

    //  Resend and poll: the reconnect (and, for SUB, the resubscription) is
    //  asynchronous.
    char buf[64];
    int rc = -1;
    for (int i = 0; i < 30 && rc < 0; ++i) {
        zmq_send (server, "ok", 2, ZMQ_DONTWAIT);
        msleep (10);
        rc = zmq_recv (client, buf, sizeof buf, ZMQ_DONTWAIT);
    }
    TEST_ASSERT_EQUAL_INT (2, rc);

    test_context_socket_close_zero_linger (server);
    test_context_socket_close_zero_linger (client);
}

void test_reconnect_after_protocol_error ()
{
    test_reconnect_after_protocol_error (ZMQ_PUB, ZMQ_SUB);
    test_reconnect_after_protocol_error (ZMQ_DEALER, ZMQ_DEALER);
    test_reconnect_after_protocol_error (ZMQ_PUSH, ZMQ_PULL);
}

//  ---------------------------------------------------------------------------
//  Over-broad erasure guard, the complement of the aliasing test: a protocol
//  error on one endpoint must leave a connection to a *different* endpoint
//  entirely alone.
void test_other_endpoint_unaffected_by_protocol_error ()
{
    char endpoint_a[MAX_SOCKET_STRING], endpoint_b[MAX_SOCKET_STRING];

    void *server_a = test_context_socket (ZMQ_PUSH);
    bind_loopback_ipv4 (server_a, endpoint_a, sizeof endpoint_a);
    void *server_b = test_context_socket (ZMQ_PUSH);
    bind_loopback_ipv4 (server_b, endpoint_b, sizeof endpoint_b);

    void *client = test_context_socket (ZMQ_PULL);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      client, ZMQ_MAXMSGSIZE, &max_msg_size, sizeof max_msg_size));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      client, ZMQ_RECONNECT_IVL, &no_reconnect, sizeof no_reconnect));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (client, endpoint_a));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (client, endpoint_b));
    msleep (SETTLE_TIME);

    send_string_expect_success (server_b, "b-before", 0);
    recv_string_expect_success (client, "b-before", 0);

    //  Blow up endpoint A only.
    trigger_protocol_error (server_a);

    //  A is gone ...
    TEST_ASSERT_FAILURE_ERRNO (ENOENT, zmq_disconnect (client, endpoint_a));
    //  ... B is untouched and still carrying data.
    send_string_expect_success (server_b, "b-after", 0);
    recv_string_expect_success (client, "b-after", 0);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_disconnect (client, endpoint_b));

    test_context_socket_close_zero_linger (server_a);
    test_context_socket_close_zero_linger (server_b);
    test_context_socket_close_zero_linger (client);
}

//  ---------------------------------------------------------------------------
//  An explicit zmq_disconnect() racing the internal teardown must be safe. The
//  two run on different threads and either may win, so the call may legitimately
//  report success (it got there first) or ENOENT (the teardown did). What must
//  not happen is a crash, an assertion, or a double erase -- this is the test
//  worth running under ASAN/TSAN.
void test_explicit_disconnect_races_protocol_error ()
{
    char endpoint[MAX_SOCKET_STRING];
    void *server, *client;
    setup_pipe (&server, &client, ZMQ_PUSH, ZMQ_PULL, endpoint,
                sizeof endpoint);

    //  Fire the oversized frame and immediately disconnect, without the settle
    //  that trigger_protocol_error() would add.
    char big_msg[OVERSIZED_LEN];
    memset (big_msg, 'x', sizeof big_msg);
    zmq_send (server, big_msg, sizeof big_msg, ZMQ_DONTWAIT);

    const int rc = zmq_disconnect (client, endpoint);
    if (rc == -1)
        TEST_ASSERT_EQUAL_INT (ENOENT, errno);
    else
        TEST_ASSERT_EQUAL_INT (0, rc);

    msleep (SETTLE_TIME);

    //  Whoever won, the endpoint is gone now and stays gone.
    TEST_ASSERT_FAILURE_ERRNO (ENOENT, zmq_disconnect (client, endpoint));

    test_context_socket_close_zero_linger (server);
    test_context_socket_close_zero_linger (client);
}

//  ---------------------------------------------------------------------------
//  The teardown is transport-independent: nothing about it is specific to TCP,
//  and in particular it does not depend on TCP's deferred address resolution.
#if !defined(ZMQ_HAVE_WINDOWS) && !defined(ZMQ_HAVE_OPENVMS)                   \
  && !defined(ZMQ_HAVE_VXWORKS)
void test_protocol_error_over_ipc ()
{
    char endpoint[MAX_SOCKET_STRING];
    make_random_ipc_endpoint (endpoint);

    void *server = test_context_socket (ZMQ_PUSH);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (server, endpoint));

    void *client = test_context_socket (ZMQ_PULL);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      client, ZMQ_MAXMSGSIZE, &max_msg_size, sizeof max_msg_size));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      client, ZMQ_RECONNECT_IVL, &no_reconnect, sizeof no_reconnect));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (client, endpoint));
    msleep (SHORT_SETTLE_TIME);

    send_string_expect_success (server, "in-limit", 0);
    recv_string_expect_success (client, "in-limit", 0);

    trigger_protocol_error (server);

    TEST_ASSERT_FAILURE_ERRNO (ENOENT, zmq_disconnect (client, endpoint));

    test_context_socket_close_zero_linger (server);
    test_context_socket_close_zero_linger (client);
}
#endif

//  ---------------------------------------------------------------------------
//  Handshake-time protocol errors, and the line between teardown and reporting.
//
//  A ZAP 400 rejection fails the connection while the mechanism is still in
//  'error' rather than 'ready' state -- a protocol error, but not a
//  post-handshake one. Such a failure leaves exactly the same zombie entry, so
//  the endpoint must be de-registered here too: the teardown is not conditional
//  on how far the connection got.
static void zap_reject_handler (void * /*unused_*/)
{
    void *handler = zmq_socket (get_test_context (), ZMQ_REP);
    TEST_ASSERT_NOT_NULL (handler);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (handler, "inproc://zeromq.zap.01"));

    for (;;) {
        char *version = s_recv (handler);
        if (!version)
            break; //  ETERM: context is terminating, exit cleanly
        char *sequence = s_recv (handler);
        //  Drain the remaining 4 request parts (domain, address, identity,
        //  mechanism)
        for (int i = 0; i < 4; ++i) {
            char *part = s_recv (handler);
            free (part);
        }
        zmq_send (handler, version, strlen (version), ZMQ_SNDMORE);
        zmq_send (handler, sequence, strlen (sequence), ZMQ_SNDMORE);
        zmq_send (handler, "400", 3, ZMQ_SNDMORE);
        zmq_send (handler, "Rejected", 8, ZMQ_SNDMORE);
        zmq_send (handler, "", 0, ZMQ_SNDMORE);
        zmq_send (handler, "", 0, 0);
        free (version);
        free (sequence);
    }
    close_zero_linger (handler);
}

void test_handshake_protocol_error_deregisters_endpoint ()
{
    char endpoint[MAX_SOCKET_STRING];

    //  Bind the ZAP endpoint before any connection attempt can query it.
    void *zap_thread = zmq_threadstart (zap_reject_handler, NULL);
    msleep (SHORT_SETTLE_TIME);

    void *server = test_context_socket (ZMQ_DEALER);
    //  Sets ZMQ_ZAP_DOMAIN, which activates ZAP for the NULL mechanism.
    socket_config_null_server (server, NULL);
    bind_loopback_ipv4 (server, endpoint, sizeof endpoint);

    void *client = test_context_socket (ZMQ_DEALER);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      client, ZMQ_RECONNECT_IVL, &no_reconnect, sizeof no_reconnect));

    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (client, endpoint));
    msleep (SETTLE_TIME); //  allow the ZAP round-trip and the teardown

    //  The endpoint must have been de-registered: an auth rejection leaves the
    //  same zombie as any other protocol error.
    TEST_ASSERT_FAILURE_ERRNO (ENOENT, zmq_disconnect (client, endpoint));

    test_context_socket_close_zero_linger (server);
    test_context_socket_close_zero_linger (client);

    //  Terminate the context before joining the ZAP thread so ETERM wakes the
    //  handler's recv loop and it can exit. tearDown() calling
    //  teardown_test_context() again is a safe no-op.
    teardown_test_context ();
    zmq_threadclose (zap_thread);
}

int main ()
{
    setup_test_environment (120); //120sec for execution alarm

    UNITY_BEGIN ();
    RUN_TEST (test_sibling_connection_survives_protocol_error);
    RUN_TEST (test_endpoint_deregistered_after_protocol_error);
    RUN_TEST (test_reconnect_after_protocol_error_via_hostname);
    RUN_TEST (test_reconnect_after_protocol_error);
    RUN_TEST (test_other_endpoint_unaffected_by_protocol_error);
    RUN_TEST (test_explicit_disconnect_races_protocol_error);
#if !defined(ZMQ_HAVE_WINDOWS) && !defined(ZMQ_HAVE_OPENVMS)                   \
  && !defined(ZMQ_HAVE_VXWORKS)
    RUN_TEST (test_protocol_error_over_ipc);
#endif
    RUN_TEST (test_handshake_protocol_error_deregisters_endpoint);

    return UNITY_END ();
}
