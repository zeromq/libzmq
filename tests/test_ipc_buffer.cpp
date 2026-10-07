/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_monitoring.hpp"
#include "testutil_unity.hpp"

#include <string.h>

#if defined ZMQ_HAVE_WINDOWS
#include <afunix.h>
typedef int test_socklen_t;
#else
#include <sys/socket.h>
#include <sys/un.h>
typedef socklen_t test_socklen_t;
#endif

SETUP_TEARDOWN_TESTCONTEXT

//  ZMQ_SNDBUF and ZMQ_RCVBUF must reach the kernel socket of an ipc
//  connection, on both its ends: the socket accepted by the listener (bind)
//  and the one opened by the connecter (connect).
//
//  The kernel is free to adjust the requested size: Linux doubles it and
//  caps it to net.core.[rw]mem_max, other systems round it. So the test
//  does not compare against the requested size, but against what a plain
//  AF_UNIX stream socket reports after the same setsockopt() call.

static int get_buffer (fd_t fd_, int option_)
{
    int value = 0;
    test_socklen_t len = sizeof value;
    TEST_ASSERT_SUCCESS_RAW_ERRNO (getsockopt (
      fd_, SOL_SOCKET, option_, reinterpret_cast<char *> (&value), &len));
    return value;
}

static void set_buffer (fd_t fd_, int option_, int value_)
{
    TEST_ASSERT_SUCCESS_RAW_ERRNO (setsockopt (
      fd_, SOL_SOCKET, option_, as_setsockopt_opt_t (&value_), sizeof value_));
}

struct buffer_sizes_t
{
    int request_sndbuf, request_rcvbuf; //  what we ask libzmq for
    int expect_sndbuf, expect_rcvbuf;   //  what the kernel then reports
};

//  A request that the kernel visibly honours (4x its default), and the
//  values it then reports, taken from a plain AF_UNIX socket.
static buffer_sizes_t reference_sizes ()
{
    const fd_t s = socket (AF_UNIX, SOCK_STREAM, 0);
    TEST_ASSERT_NOT_EQUAL (retired_fd, s);

    const int default_sndbuf = get_buffer (s, SO_SNDBUF);
    const int default_rcvbuf = get_buffer (s, SO_RCVBUF);
    buffer_sizes_t sizes;
    sizes.request_sndbuf = 4 * default_sndbuf;
    sizes.request_rcvbuf = 4 * default_rcvbuf;
    set_buffer (s, SO_SNDBUF, sizes.request_sndbuf);
    set_buffer (s, SO_RCVBUF, sizes.request_rcvbuf);
    sizes.expect_sndbuf = get_buffer (s, SO_SNDBUF);
    sizes.expect_rcvbuf = get_buffer (s, SO_RCVBUF);
    close (s);

    //  Otherwise the checks below would pass without the options applied
    if (sizes.expect_sndbuf == default_sndbuf
        || sizes.expect_rcvbuf == default_rcvbuf)
        TEST_IGNORE_MESSAGE ("the kernel does not resize AF_UNIX buffers");
    return sizes;
}

static void set_zmq_buffers (void *socket_, const buffer_sizes_t &sizes_)
{
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (socket_, ZMQ_SNDBUF,
                                               &sizes_.request_sndbuf,
                                               sizeof sizes_.request_sndbuf));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (socket_, ZMQ_RCVBUF,
                                               &sizes_.request_rcvbuf,
                                               sizeof sizes_.request_rcvbuf));
}

//  The file descriptor carried by the next `event_` on `socket_`'s monitor
static fd_t wait_for_fd (void *monitor_, int event_)
{
    int value = 0;
    const int event =
      get_monitor_event_with_timeout (monitor_, &value, NULL, 2000);
    TEST_ASSERT_EQUAL_INT (event_, event);
    return static_cast<fd_t> (value);
}

static void *monitor_socket (void *socket_, int event_, const char *addr_)
{
    TEST_ASSERT_SUCCESS_ERRNO (zmq_socket_monitor (socket_, addr_, event_));
    void *monitor = test_context_socket (ZMQ_PAIR);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (monitor, addr_));
    return monitor;
}

//  A large message still crosses the connection intact
static void send_large_message (void *from_, void *to_)
{
    const size_t size = 1024 * 1024;
    char *payload = static_cast<char *> (malloc (size));
    TEST_ASSERT_NOT_NULL (payload);
    memset (payload, 'x', size);
    TEST_ASSERT_EQUAL_INT (static_cast<int> (size),
                           zmq_send (from_, payload, size, 0));
    zmq_msg_t msg;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init (&msg));
    TEST_ASSERT_EQUAL_INT (static_cast<int> (size),
                           zmq_msg_recv (&msg, to_, 0));
    TEST_ASSERT_EQUAL_MEMORY (payload, zmq_msg_data (&msg), size);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg));
    free (payload);
}

void test_ipc_buffers_on_bind ()
{
    const buffer_sizes_t sizes = reference_sizes ();
    char endpoint[MAX_SOCKET_STRING];
    make_random_ipc_endpoint (endpoint);

    void *server = test_context_socket (ZMQ_PULL);
    set_zmq_buffers (server, sizes);
    void *monitor =
      monitor_socket (server, ZMQ_EVENT_ACCEPTED, "inproc://monitor-bind");
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (server, endpoint));

    void *client = test_context_socket (ZMQ_PUSH);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (client, endpoint));

    const fd_t fd = wait_for_fd (monitor, ZMQ_EVENT_ACCEPTED);
    TEST_ASSERT_EQUAL_INT (sizes.expect_sndbuf, get_buffer (fd, SO_SNDBUF));
    TEST_ASSERT_EQUAL_INT (sizes.expect_rcvbuf, get_buffer (fd, SO_RCVBUF));

    send_large_message (client, server);

    test_context_socket_close (client);
    test_context_socket_close_zero_linger (monitor);
    test_context_socket_close (server);
}

void test_ipc_buffers_on_connect ()
{
    const buffer_sizes_t sizes = reference_sizes ();
    char endpoint[MAX_SOCKET_STRING];
    make_random_ipc_endpoint (endpoint);

    void *server = test_context_socket (ZMQ_PULL);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (server, endpoint));

    void *client = test_context_socket (ZMQ_PUSH);
    set_zmq_buffers (client, sizes);
    void *monitor =
      monitor_socket (client, ZMQ_EVENT_CONNECTED, "inproc://monitor-connect");
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (client, endpoint));

    const fd_t fd = wait_for_fd (monitor, ZMQ_EVENT_CONNECTED);
    TEST_ASSERT_EQUAL_INT (sizes.expect_sndbuf, get_buffer (fd, SO_SNDBUF));
    TEST_ASSERT_EQUAL_INT (sizes.expect_rcvbuf, get_buffer (fd, SO_RCVBUF));

    send_large_message (client, server);

    test_context_socket_close (client);
    test_context_socket_close_zero_linger (monitor);
    test_context_socket_close (server);
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_ipc_buffers_on_bind);
    RUN_TEST (test_ipc_buffers_on_connect);
    return UNITY_END ();
}
