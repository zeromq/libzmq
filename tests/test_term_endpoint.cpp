/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

#include <string.h>

SETUP_TEARDOWN_TESTCONTEXT

/* Use the worst case filename size for the buffer (+1 for trailing NUL), this
 * is larger than MAX_SOCKET_STRING, which is not large enough for IPC */
#define BUF_SIZE (FILENAME_MAX + 1)

const char *ep_wc_tcp = "tcp://127.0.0.1:*";
#if !defined ZMQ_HAVE_WINDOWS && !defined ZMQ_HAVE_OPENVMS
const char *ep_wc_ipc = "ipc://*";
#endif
#if defined ZMQ_HAVE_VMCI
const char *ep_wc_vmci = "vmci://*:*";
#endif

void test_send_after_unbind_fails ()
{
    char my_endpoint[BUF_SIZE];

    //  Create infrastructure.
    void *push = test_context_socket (ZMQ_PUSH);
    bind_loopback_ipv4 (push, my_endpoint, BUF_SIZE);

    void *pull = test_context_socket (ZMQ_PULL);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (pull, my_endpoint));

    //  Pass one message through to ensure the connection is established
    send_string_expect_success (push, "ABC", 0);
    recv_string_expect_success (pull, "ABC", 0);

    //  Unbind the listening endpoint
    TEST_ASSERT_SUCCESS_ERRNO (zmq_unbind (push, my_endpoint));

    //  Allow unbind to settle
    msleep (SETTLE_TIME);

    //  Check that sending would block (there's no outbound connection)
    TEST_ASSERT_FAILURE_ERRNO (EAGAIN, zmq_send (push, "ABC", 3, ZMQ_DONTWAIT));

    //  Clean up
    test_context_socket_close (pull);
    test_context_socket_close (push);
}

void test_send_after_disconnect_fails ()
{
    //  Create infrastructure
    void *pull = test_context_socket (ZMQ_PULL);
    char my_endpoint[BUF_SIZE];
    bind_loopback_ipv4 (pull, my_endpoint, BUF_SIZE);

    void *push = test_context_socket (ZMQ_PUSH);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (push, my_endpoint));

    //  Pass one message through to ensure the connection is established.
    send_string_expect_success (push, "ABC", 0);
    recv_string_expect_success (pull, "ABC", 0);

    //  Disconnect the bound endpoint
    TEST_ASSERT_SUCCESS_ERRNO (zmq_disconnect (push, my_endpoint));

    //  Allow disconnect to settle
    msleep (SETTLE_TIME);

    //  Check that sending would block (there's no inbound connections).
    TEST_ASSERT_FAILURE_ERRNO (EAGAIN, zmq_send (push, "ABC", 3, ZMQ_DONTWAIT));

    //  Clean up
    test_context_socket_close (pull);
    test_context_socket_close (push);
}

void test_unbind_via_last_endpoint ()
{
    //  Create infrastructure (wild-card binding)
    void *push = test_context_socket (ZMQ_PUSH);
    char my_endpoint[BUF_SIZE];
    bind_loopback_ipv4 (push, my_endpoint, BUF_SIZE);

    void *pull = test_context_socket (ZMQ_PULL);

#if !defined ZMQ_HAVE_WINDOWS && !defined ZMQ_HAVE_OPENVMS
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (pull, ep_wc_ipc));
#endif
#if defined ZMQ_HAVE_VMCI
    void *req = test_context_socket (ZMQ_REQ);
    int rc = zmq_bind (req, ep_wc_vmci);
    if (rc < 0 && errno == EAFNOSUPPORT)
        TEST_IGNORE_MESSAGE ("VMCI not supported");
    TEST_ASSERT_SUCCESS_ERRNO (rc);
#endif

    // Unbind sockets binded by wild-card address
    TEST_ASSERT_SUCCESS_ERRNO (zmq_unbind (push, my_endpoint));

    size_t buf_size = 0;
    (void) buf_size;

#if !defined ZMQ_HAVE_WINDOWS && !defined ZMQ_HAVE_OPENVMS
    buf_size = sizeof (my_endpoint);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (pull, ZMQ_LAST_ENDPOINT, my_endpoint, &buf_size));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_unbind (pull, my_endpoint));
#endif
#if defined ZMQ_HAVE_VMCI
    buf_size = sizeof (my_endpoint);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (req, ZMQ_LAST_ENDPOINT, my_endpoint, &buf_size));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_unbind (req, my_endpoint));
#endif

    //  Clean up
    test_context_socket_close (pull);
    test_context_socket_close (push);
}

void test_wildcard_unbind_fails ()
{
    //  Create infrastructure (wild-card binding)
    void *push = test_context_socket (ZMQ_PUSH);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (push, ep_wc_tcp));
    void *pull = test_context_socket (ZMQ_PULL);
#if !defined ZMQ_HAVE_WINDOWS && !defined ZMQ_HAVE_OPENVMS
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (pull, ep_wc_ipc));
#endif
#if defined ZMQ_HAVE_VMCI
    void *req = test_context_socket (ZMQ_REQ);
    int rc = zmq_bind (req, ep_wc_vmci);
    if (rc < 0 && errno == EAFNOSUPPORT)
        TEST_IGNORE_MESSAGE ("VMCI not supported");
    TEST_ASSERT_SUCCESS_ERRNO (rc);
#endif

    // Sockets binded by wild-card address can't be unbinded by wild-card address
    TEST_ASSERT_FAILURE_ERRNO (ENOENT, zmq_unbind (push, ep_wc_tcp));
#if !defined ZMQ_HAVE_WINDOWS && !defined ZMQ_HAVE_OPENVMS
    TEST_ASSERT_FAILURE_ERRNO (ENOENT, zmq_unbind (pull, ep_wc_ipc));
#endif
#if defined ZMQ_HAVE_VMCI
    TEST_ASSERT_FAILURE_ERRNO (ENOENT, zmq_unbind (req, ep_wc_vmci));
#endif

    //  Clean up
    test_context_socket_close (pull);
    test_context_socket_close (push);
}

//  A socket that is not subject to the single-connect guard may hold several
//  connections to one URI, and the endpoint registry is a multimap keyed on
//  that URI. A single zmq_disconnect() call takes down *all* of them: the
//  implementation erases the whole equal_range for the key, and the caller has
//  no way to name one connection rather than another. Existing semantics.
//
//  This is ensuring no change to existing API semantics when we're changing
//  the internal term_endpoint command to carry the owning object* rather than
//  the URI. Erase-all is a sensible answer for an explicit
//  application-initiated zmq_disconnect - the caller asked to remove
//  connections by endpoint string, and gets all matching connections - but it
//  is the wrong answer for a single connection dying of a protocol error,
//  where the siblings are healthy and should survive. Erasing by owning object
//  on the internal path is what separates the two.
void test_disconnect_all_connections_to_same_endpoint ()
{
    void *push = test_context_socket (ZMQ_PUSH);
    char my_endpoint[BUF_SIZE];
    bind_loopback_ipv4 (push, my_endpoint, BUF_SIZE);

    //  ZMQ_PULL is not one of the single-connect types (DEALER/SUB/PUB/REQ),
    //  so both connects create a real connection.
    void *pull = test_context_socket (ZMQ_PULL);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (pull, my_endpoint));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (pull, my_endpoint));

    //  Pass one message through to ensure the connections are established.
    send_string_expect_success (push, "ABC", 0);
    recv_string_expect_success (pull, "ABC", 0);

    //  One disconnect call is enough to remove both entries ...
    TEST_ASSERT_SUCCESS_ERRNO (zmq_disconnect (pull, my_endpoint));
    msleep (SETTLE_TIME);

    //  ... after which the endpoint is unknown to this socket, even though it was
    //  connected twice.
    TEST_ASSERT_FAILURE_ERRNO (ENOENT, zmq_disconnect (pull, my_endpoint));

    //  And nothing arrives any more: there is no surviving pipe to carry it.
    char buf[16];
    for (int i = 0; i < 10; ++i) {
        zmq_send (push, "DEF", 3, ZMQ_DONTWAIT);
        msleep (10);
        TEST_ASSERT_FAILURE_ERRNO (
          EAGAIN, zmq_recv (pull, buf, sizeof buf, ZMQ_DONTWAIT));
    }

    //  Clean up
    test_context_socket_close (pull);
    test_context_socket_close (push);
}

//  zmq_disconnect() matches on the exact string given to zmq_connect(), not on
//  the address it resolves to. Connecting by name and disconnecting by name
//  works; disconnecting the same connection by its IP does not, and reports
//  ENOENT.
//
//  This is long-standing behaviour: the registry is keyed on what the caller
//  said, so the caller can always undo what it did without having to know how the
//  name resolved (it could resolve in a different way).
//
//  Bind/accept side is different as the user needs to getopt ZMQ_LAST_ENDPOINT
//  if they use interface wildcards anyway. (Again, existing limitation).
void test_connect_disconnect_hostname_round_trip ()
{
    void *pull = test_context_socket (ZMQ_PULL);
    char bound_endpoint[BUF_SIZE];
    bind_loopback_ipv4 (pull, bound_endpoint, BUF_SIZE);

    //  Re-spell the bound endpoint via the "localhost" alias.
    const char *port = strrchr (bound_endpoint, ':');
    TEST_ASSERT_NOT_NULL (port);
    char host_endpoint[BUF_SIZE];
    snprintf (host_endpoint, sizeof host_endpoint, "tcp://localhost%s", port);

    void *push = test_context_socket (ZMQ_PUSH);
    if (zmq_connect (push, host_endpoint) == -1) {
        test_context_socket_close (pull);
        test_context_socket_close (push);
        TEST_IGNORE_MESSAGE ("'localhost' does not resolve here");
    }

    //  Confirm the name really reached the IPv4 loopback listener before relying
    //  on it; skip rather than fail on hosts that resolve it elsewhere.
    send_string_expect_success (push, "ABC", 0);
    char buf[16];
    int rc = -1;
    for (int i = 0; i < 20 && rc < 0; ++i) {
        rc = zmq_recv (pull, buf, sizeof buf, ZMQ_DONTWAIT);
        if (rc < 0)
            msleep (10);
    }
    if (rc < 0) {
        test_context_socket_close_zero_linger (pull);
        test_context_socket_close_zero_linger (push);
        TEST_IGNORE_MESSAGE (
          "'localhost' does not resolve to the IPv4 loopback");
    }

    //  The resolved address is not a key: this connection is registered under
    //  the name it was made with.
    TEST_ASSERT_FAILURE_ERRNO (ENOENT, zmq_disconnect (push, bound_endpoint));

    //  The name it was made with is.
    TEST_ASSERT_SUCCESS_ERRNO (zmq_disconnect (push, host_endpoint));

    //  Clean up
    test_context_socket_close (pull);
    test_context_socket_close (push);
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_send_after_unbind_fails);
    RUN_TEST (test_send_after_disconnect_fails);
    RUN_TEST (test_unbind_via_last_endpoint);
    RUN_TEST (test_wildcard_unbind_fails);
    RUN_TEST (test_disconnect_all_connections_to_same_endpoint);
    RUN_TEST (test_connect_disconnect_hostname_round_trip);
    return UNITY_END ();
}
