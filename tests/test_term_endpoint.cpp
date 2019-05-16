/*
    Copyright (c) 2007-2016 Contributors as noted in the AUTHORS file

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
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (req, ep_wc_vmci));
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
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (req, ep_wc_vmci));
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
