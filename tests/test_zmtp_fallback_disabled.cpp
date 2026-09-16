/* SPDX-License-Identifier: MPL-2.0 */

// Only built when ZMQ_HAVE_ZMTP_FALLBACK_DISABLED is set (see
// ENABLE_ZMTP_FALLBACK in CMakeLists.txt / --disable-zmtp-fallback in
// configure.ac). Verifies that with the fallback disabled, a peer that
// does not speak ZMTP 3.x (in this case, one sending unversioned/ZMTP 1.0
// framing, as a non-ZMQ TCP client such as a port scanner would produce
// by simply writing arbitrary bytes) is rejected outright, and that this
// happens even with NO ZAP domain configured -- i.e. the protection does
// not depend on ZAP being set up at all, unlike the zap_enabled()-based
// rejection that already existed for ZAP-enabled sockets.

#include "testutil.hpp"
#include "testutil_unity.hpp"
#include "testutil_monitoring.hpp"

#if defined(ZMQ_HAVE_WINDOWS)
#include <winsock2.h>
#define close closesocket
#else
#include <sys/socket.h>
#include <unistd.h>
#endif

void setUp ()
{
    setup_test_context ();
}

void tearDown ()
{
    teardown_test_context ();
}

// With no ZAP domain and a plain NULL-mechanism server, a peer sending
// unversioned ZMTP 1.0 framing must be rejected -- this is the case that
// is normally allowed through (see test_security_null.cpp's
// test_vanilla_socket, which asserts the message is simply not received
// by the app but does not assert the connection itself was rejected).
// Here we assert on the stronger, more direct signal: the server closes
// the raw TCP connection.
void test_unversioned_zmtp1_rejected_without_zap ()
{
    void *server = test_context_socket (ZMQ_SUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (server, ZMQ_SUBSCRIBE, "", 0));
    char my_endpoint[MAX_SOCKET_STRING];
    bind_loopback_ipv4 (server, my_endpoint, sizeof my_endpoint);

    fd_t s = connect_socket (my_endpoint);

    // Unversioned ZMTP 1.0 framing: [size:1][flags:1][body:(size-1)].
    // First byte is not 0xff, so a fallback-enabled engine would treat
    // this peer as ZMTP 1.0 rather than rejecting it outright.
    const char frame1[] = "\x03\x00ID"; // routing-id frame (4 bytes)
    const char frame2[] =
      "\x14\x00RAW-GARBAGE-PAYLOAD"; // app-visible frame if fallback runs (22 bytes)
    send (s, frame1, 4, 0);
    send (s, frame2, 22, 0);

    // The connection must be closed by the server promptly. recv()
    // returning 0 is EOF (orderly close); a negative return with a
    // connection-reset-style errno also counts as rejection.
    char buf[16];
    msleep (SETTLE_TIME);
    const int rc = recv (s, buf, sizeof (buf), 0);
    TEST_ASSERT_TRUE (rc == 0 || rc < 0);

    close (s);
    test_context_socket_close_zero_linger (server);
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_unversioned_zmtp1_rejected_without_zap);
    return UNITY_END ();
}
