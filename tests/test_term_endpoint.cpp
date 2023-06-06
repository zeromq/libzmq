/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

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

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_send_after_unbind_fails);
    RUN_TEST (test_send_after_disconnect_fails);
    RUN_TEST (test_unbind_via_last_endpoint);
    RUN_TEST (test_wildcard_unbind_fails);
    return UNITY_END ();
}
