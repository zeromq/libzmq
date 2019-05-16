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
#include "testutil_unity.hpp"

#include <limits.h>

#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

SETUP_TEARDOWN_TESTCONTEXT

fd_t get_fd (void *socket_)
{
    fd_t fd;
    size_t fd_size = sizeof fd;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_getsockopt (socket_, ZMQ_FD, &fd, &fd_size));
    return fd;
}

void test_null_poller_pointers_destroy_direct ()
{
    TEST_ASSERT_FAILURE_ERRNO (EFAULT, zmq_poller_destroy (NULL));
}

void test_null_poller_pointers_destroy_indirect ()
{
    void *null_poller = NULL;
    TEST_ASSERT_FAILURE_ERRNO (EFAULT, zmq_poller_destroy (&null_poller));
}

void test_null_poller_pointers_add_direct ()
{
    void *socket = test_context_socket (ZMQ_PAIR);
    TEST_ASSERT_FAILURE_ERRNO (EFAULT,
                               zmq_poller_add (NULL, socket, NULL, ZMQ_POLLIN));
    test_context_socket_close (socket);
}

void test_null_poller_pointers_add_indirect ()
{
    void *null_poller = NULL;
    void *socket = test_context_socket (ZMQ_PAIR);
    TEST_ASSERT_FAILURE_ERRNO (
      EFAULT, zmq_poller_add (&null_poller, socket, NULL, ZMQ_POLLIN));
    test_context_socket_close (socket);
}

void test_null_poller_pointers_modify_direct ()
{
    void *socket = test_context_socket (ZMQ_PAIR);
    TEST_ASSERT_FAILURE_ERRNO (EFAULT,
                               zmq_poller_modify (NULL, socket, ZMQ_POLLIN));
    test_context_socket_close (socket);
}

void test_null_poller_pointers_modify_indirect ()
{
    void *null_poller = NULL;
    void *socket = test_context_socket (ZMQ_PAIR);
    TEST_ASSERT_FAILURE_ERRNO (
      EFAULT, zmq_poller_modify (&null_poller, socket, ZMQ_POLLIN));
    test_context_socket_close (socket);
}

void test_null_poller_pointers_remove_direct ()
{
    void *socket = test_context_socket (ZMQ_PAIR);
    TEST_ASSERT_FAILURE_ERRNO (EFAULT, zmq_poller_remove (NULL, socket));
    test_context_socket_close (socket);
}

void test_null_poller_pointers_remove_indirect ()
{
    void *null_poller = NULL;
    void *socket = test_context_socket (ZMQ_PAIR);
    TEST_ASSERT_FAILURE_ERRNO (EFAULT,
                               zmq_poller_remove (&null_poller, socket));
    test_context_socket_close (socket);
}

void test_null_poller_pointers_add_fd_direct ()
{
    void *socket = test_context_socket (ZMQ_PAIR);
    const fd_t fd = get_fd (socket);

    TEST_ASSERT_FAILURE_ERRNO (EFAULT,
                               zmq_poller_add_fd (NULL, fd, NULL, ZMQ_POLLIN));
    test_context_socket_close (socket);
}

void test_null_poller_pointers_add_fd_indirect ()
{
    void *socket = test_context_socket (ZMQ_PAIR);
    const fd_t fd = get_fd (socket);
    void *null_poller = NULL;
    TEST_ASSERT_FAILURE_ERRNO (
      EFAULT, zmq_poller_add_fd (&null_poller, fd, NULL, ZMQ_POLLIN));
    test_context_socket_close (socket);
}

void test_null_poller_pointers_modify_fd_direct ()
{
    void *socket = test_context_socket (ZMQ_PAIR);
    const fd_t fd = get_fd (socket);
    TEST_ASSERT_FAILURE_ERRNO (EFAULT,
                               zmq_poller_modify_fd (NULL, fd, ZMQ_POLLIN));
    test_context_socket_close (socket);
}

void test_null_poller_pointers_modify_fd_indirect ()
{
    void *socket = test_context_socket (ZMQ_PAIR);
    const fd_t fd = get_fd (socket);
    void *null_poller = NULL;
    TEST_ASSERT_FAILURE_ERRNO (
      EFAULT, zmq_poller_modify_fd (&null_poller, fd, ZMQ_POLLIN));
    test_context_socket_close (socket);
}

void test_null_poller_pointers_remove_fd_direct ()
{
    void *socket = test_context_socket (ZMQ_PAIR);
    const fd_t fd = get_fd (socket);
    TEST_ASSERT_FAILURE_ERRNO (EFAULT, zmq_poller_remove_fd (NULL, fd));
    test_context_socket_close (socket);
}

void test_null_poller_pointers_remove_fd_indirect ()
{
    void *socket = test_context_socket (ZMQ_PAIR);
    const fd_t fd = get_fd (socket);
    void *null_poller = NULL;
    TEST_ASSERT_FAILURE_ERRNO (EFAULT, zmq_poller_remove_fd (&null_poller, fd));
    test_context_socket_close (socket);
}

void test_null_poller_pointers_wait_direct ()
{
    zmq_poller_event_t event;
    TEST_ASSERT_FAILURE_ERRNO (EFAULT, zmq_poller_wait (NULL, &event, 0));
}

void test_null_poller_pointers_wait_indirect ()
{
    zmq_poller_event_t event;
    void *null_poller = NULL;
    TEST_ASSERT_FAILURE_ERRNO (EFAULT,
                               zmq_poller_wait (&null_poller, &event, 0));
}

void test_null_poller_pointers_wait_all_direct ()
{
    zmq_poller_event_t event;
    TEST_ASSERT_FAILURE_ERRNO (EFAULT,
                               zmq_poller_wait_all (NULL, &event, 1, 0));
}

void test_null_poller_pointers_wait_all_indirect ()
{
    zmq_poller_event_t event;
    void *null_poller = NULL;
    TEST_ASSERT_FAILURE_ERRNO (
      EFAULT, zmq_poller_wait_all (&null_poller, &event, 1, 0));
}

void test_null_poller_pointer_poller_fd ()
{
    void *null_poller = NULL;
    zmq_fd_t fd;
    TEST_ASSERT_FAILURE_ERRNO (EFAULT, zmq_poller_fd (&null_poller, &fd));
}

void test_null_socket_pointers ()
{
    void *poller = zmq_poller_new ();
    TEST_ASSERT_NOT_NULL (poller);

    TEST_ASSERT_FAILURE_ERRNO (ENOTSOCK,
                               zmq_poller_add (poller, NULL, NULL, ZMQ_POLLIN));

    TEST_ASSERT_FAILURE_ERRNO (ENOTSOCK,
                               zmq_poller_modify (poller, NULL, ZMQ_POLLIN));

    TEST_ASSERT_FAILURE_ERRNO (ENOTSOCK, zmq_poller_remove (poller, NULL));

    fd_t null_socket_fd = retired_fd;

    TEST_ASSERT_FAILURE_ERRNO (
      EBADF, zmq_poller_add_fd (poller, null_socket_fd, NULL, ZMQ_POLLIN));

    TEST_ASSERT_FAILURE_ERRNO (
      EBADF, zmq_poller_modify_fd (poller, null_socket_fd, ZMQ_POLLIN));

    TEST_ASSERT_FAILURE_ERRNO (EBADF,
                               zmq_poller_remove_fd (poller, null_socket_fd));

    TEST_ASSERT_SUCCESS_ERRNO (zmq_poller_destroy (&poller));
}

typedef void (*extra_poller_socket_func_t) (void *poller_, void *socket_);

void test_with_empty_poller (extra_poller_socket_func_t extra_func_)
{
    void *socket = test_context_socket (ZMQ_PAIR);

    void *poller = zmq_poller_new ();
    TEST_ASSERT_NOT_NULL (poller);

    extra_func_ (poller, socket);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_poller_destroy (&poller));

    test_context_socket_close (socket);
}

typedef void (*extra_poller_func_t) (void *poller_);

void test_with_valid_poller (extra_poller_func_t extra_func_)
{
    void *socket = test_context_socket (ZMQ_PAIR);

    void *poller = zmq_poller_new ();
    TEST_ASSERT_NOT_NULL (poller);

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_poller_add (poller, socket, NULL, ZMQ_POLLIN));

    extra_func_ (poller);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_poller_destroy (&poller));

    test_context_socket_close (socket);
}

void test_call_poller_fd_no_signaler ()
{
    void *socket = test_context_socket (ZMQ_PAIR);

    void *poller = zmq_poller_new ();
    TEST_ASSERT_NOT_NULL (poller);

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_poller_add (poller, socket, NULL, ZMQ_POLLIN));

    zmq_fd_t fd;
    TEST_ASSERT_FAILURE_ERRNO (EINVAL, zmq_poller_fd (poller, &fd));

    TEST_ASSERT_SUCCESS_ERRNO (zmq_poller_destroy (&poller));

    test_context_socket_close (socket);
}

void test_call_poller_fd ()
{
    void *socket = test_context_socket (ZMQ_CLIENT);

    void *poller = zmq_poller_new ();
    TEST_ASSERT_NOT_NULL (poller);

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_poller_add (poller, socket, NULL, ZMQ_POLLIN));

    zmq_fd_t fd;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_poller_fd (poller, &fd));

    TEST_ASSERT_SUCCESS_ERRNO (zmq_poller_destroy (&poller));

    test_context_socket_close (socket);
}

void call_poller_wait_null_event_fails (void *poller_)
{
    TEST_ASSERT_FAILURE_ERRNO (EFAULT, zmq_poller_wait (poller_, NULL, 0));
}

void call_poller_wait_all_null_event_fails_event_count_nonzero (void *poller_)
{
    TEST_ASSERT_FAILURE_ERRNO (EFAULT,
                               zmq_poller_wait_all (poller_, NULL, 1, 0));
}

void call_poller_wait_all_null_event_fails_event_count_zero (void *poller_)
{
#if 0
    //  TODO this causes an assertion, which is not consistent if the number
    //  of events may be 0, the pointer should be allowed to by NULL in that
    //  case too
    TEST_ASSERT_SUCCESS_ERRNO (zmq_poller_wait_all (poller, NULL, 0, 0));
#endif
}

#define TEST_CASE_FUNC_PARAM(name, func)                                       \
    void test_##name () { func (name); }

TEST_CASE_FUNC_PARAM (call_poller_wait_null_event_fails, test_with_valid_poller)
TEST_CASE_FUNC_PARAM (call_poller_wait_all_null_event_fails_event_count_nonzero,
                      test_with_valid_poller)
TEST_CASE_FUNC_PARAM (call_poller_wait_all_null_event_fails_event_count_zero,
                      test_with_valid_poller)

void call_poller_add_twice_fails (void *poller_, void *socket_)
{
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_poller_add (poller_, socket_, NULL, ZMQ_POLLIN));

    //  attempt to add the same socket twice
    TEST_ASSERT_FAILURE_ERRNO (
      EINVAL, zmq_poller_add (poller_, socket_, NULL, ZMQ_POLLIN));

    TEST_ASSERT_SUCCESS_ERRNO (zmq_poller_remove (poller_, socket_));
}

void call_poller_remove_unregistered_fails (void *poller_, void *socket_)
{
    //  attempt to remove socket that is not present
    TEST_ASSERT_FAILURE_ERRNO (EINVAL, zmq_poller_remove (poller_, socket_));
}

void call_poller_modify_unregistered_fails (void *poller_, void *socket_)
{
    //  attempt to modify socket that is not present
    TEST_ASSERT_FAILURE_ERRNO (
      EINVAL, zmq_poller_modify (poller_, socket_, ZMQ_POLLIN));
}

void call_poller_add_no_events (void *poller_, void *socket_)
{
    //  add a socket with no events initially (may be activated later with
    //  zmq_poller_modify)
    TEST_ASSERT_SUCCESS_ERRNO (zmq_poller_add (poller_, socket_, NULL, 0));
    //  TODO test that no events are signalled
}

void call_poller_modify_no_events (void *poller_, void *socket_)
{
    //  deactivates all events for a socket temporarily (may be activated again
    //  later with zmq_poller_modify)
    zmq_poller_add (poller_, socket_, NULL, ZMQ_POLLIN);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_poller_modify (poller_, socket_, 0));
    //  TODO test that no events are signalled
}

void call_poller_add_fd_twice_fails (void *poller_, void * /*zeromq_socket*/)
{
    fd_t plain_socket = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_poller_add_fd (poller_, plain_socket, NULL, ZMQ_POLLIN));

    //  attempt to add the same plain socket twice
    TEST_ASSERT_FAILURE_ERRNO (
      EINVAL, zmq_poller_add_fd (poller_, plain_socket, NULL, ZMQ_POLLIN));

    TEST_ASSERT_SUCCESS_ERRNO (zmq_poller_remove_fd (poller_, plain_socket));

    TEST_ASSERT_SUCCESS_ERRNO (close (plain_socket));
}

void call_poller_remove_fd_unregistered_fails (void *poller_,
                                               void * /*zeromq_socket*/)
{
    fd_t plain_socket = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);

    //  attempt to remove plain socket that is not present
    TEST_ASSERT_FAILURE_ERRNO (EINVAL,
                               zmq_poller_remove_fd (poller_, plain_socket));

    TEST_ASSERT_SUCCESS_ERRNO (close (plain_socket));
}

void call_poller_modify_fd_unregistered_fails (void *poller_,
                                               void * /*zeromq_socket*/)
{
    fd_t plain_socket = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);

    //  attempt to remove plain socket that is not present
    TEST_ASSERT_FAILURE_ERRNO (
      EINVAL, zmq_poller_modify_fd (poller_, plain_socket, ZMQ_POLLIN));

    TEST_ASSERT_SUCCESS_ERRNO (close (plain_socket));
}

void call_poller_add_invalid_events_fails (void *poller_, void *zeromq_socket_)
{
    TEST_ASSERT_FAILURE_ERRNO (
      EINVAL, zmq_poller_add (poller_, zeromq_socket_, NULL, SHRT_MAX));
}

void call_poller_modify_invalid_events_fails (void *poller_,
                                              void *zeromq_socket_)
{
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_poller_add (poller_, zeromq_socket_, NULL, 0));

    TEST_ASSERT_FAILURE_ERRNO (
      EINVAL, zmq_poller_modify (poller_, zeromq_socket_, SHRT_MAX));
}

void call_poller_add_fd_invalid_events_fails (void *poller_,
                                              void * /*zeromq_socket*/)
{
    fd_t plain_socket = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
    TEST_ASSERT_FAILURE_ERRNO (
      EINVAL, zmq_poller_add_fd (poller_, plain_socket, NULL, SHRT_MAX));

    TEST_ASSERT_SUCCESS_ERRNO (close (plain_socket));
}

void call_poller_modify_fd_invalid_events_fails (void *poller_,
                                                 void * /*zeromq_socket*/)
{
    fd_t plain_socket = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_poller_add_fd (poller_, plain_socket, NULL, 0));
    TEST_ASSERT_FAILURE_ERRNO (
      EINVAL, zmq_poller_modify_fd (poller_, plain_socket, SHRT_MAX));

    TEST_ASSERT_SUCCESS_ERRNO (close (plain_socket));
}

TEST_CASE_FUNC_PARAM (call_poller_add_twice_fails, test_with_empty_poller)
TEST_CASE_FUNC_PARAM (call_poller_remove_unregistered_fails,
                      test_with_empty_poller)
TEST_CASE_FUNC_PARAM (call_poller_modify_unregistered_fails,
                      test_with_empty_poller)
TEST_CASE_FUNC_PARAM (call_poller_add_no_events, test_with_empty_poller)
TEST_CASE_FUNC_PARAM (call_poller_modify_no_events, test_with_empty_poller)
TEST_CASE_FUNC_PARAM (call_poller_add_fd_twice_fails, test_with_empty_poller)
TEST_CASE_FUNC_PARAM (call_poller_remove_fd_unregistered_fails,
                      test_with_empty_poller)
TEST_CASE_FUNC_PARAM (call_poller_modify_fd_unregistered_fails,
                      test_with_empty_poller)

TEST_CASE_FUNC_PARAM (call_poller_add_invalid_events_fails,
                      test_with_empty_poller)
TEST_CASE_FUNC_PARAM (call_poller_modify_invalid_events_fails,
                      test_with_empty_poller)
TEST_CASE_FUNC_PARAM (call_poller_add_fd_invalid_events_fails,
                      test_with_empty_poller)
TEST_CASE_FUNC_PARAM (call_poller_modify_fd_invalid_events_fails,
                      test_with_empty_poller)

void call_poller_wait_empty_with_timeout_fails (void *poller_,
                                                void * /*socket*/)
{
    zmq_poller_event_t event;
    // waiting on poller with no registered sockets should report error
    TEST_ASSERT_FAILURE_ERRNO (EAGAIN, zmq_poller_wait (poller_, &event, 0));
}

void call_poller_wait_empty_without_timeout_fails (void *poller_,
                                                   void * /*socket*/)
{
    zmq_poller_event_t event;
    //  this would never be able to return since no socket was registered, and should yield an error
    TEST_ASSERT_FAILURE_ERRNO (EFAULT, zmq_poller_wait (poller_, &event, -1));
}

void call_poller_wait_all_empty_negative_count_fails (void *poller_,
                                                      void * /*socket*/)
{
    zmq_poller_event_t event;
    TEST_ASSERT_FAILURE_ERRNO (EINVAL,
                               zmq_poller_wait_all (poller_, &event, -1, 0));
}

void call_poller_wait_all_empty_without_timeout_fails (void *poller_,
                                                       void * /*socket*/)
{
    zmq_poller_event_t event;
    TEST_ASSERT_FAILURE_ERRNO (EAGAIN,
                               zmq_poller_wait_all (poller_, &event, 0, 0));
}

void call_poller_wait_all_empty_with_timeout_fails (void *poller_,
                                                    void * /*socket*/)
{
    zmq_poller_event_t event;
    //  this would never be able to return since no socket was registered, and should yield an error
    TEST_ASSERT_FAILURE_ERRNO (EFAULT,
                               zmq_poller_wait_all (poller_, &event, 0, -1));
}

TEST_CASE_FUNC_PARAM (call_poller_wait_empty_with_timeout_fails,
                      test_with_empty_poller)
TEST_CASE_FUNC_PARAM (call_poller_wait_empty_without_timeout_fails,
                      test_with_empty_poller)
TEST_CASE_FUNC_PARAM (call_poller_wait_all_empty_negative_count_fails,
                      test_with_empty_poller)
TEST_CASE_FUNC_PARAM (call_poller_wait_all_empty_without_timeout_fails,
                      test_with_empty_poller)
TEST_CASE_FUNC_PARAM (call_poller_wait_all_empty_with_timeout_fails,
                      test_with_empty_poller)

void test_poll_basic ()
{
    //  Create few sockets
    void *vent = test_context_socket (ZMQ_PUSH);

    size_t len = MAX_SOCKET_STRING;
    char my_endpoint[MAX_SOCKET_STRING];
    bind_loopback_ipv4 (vent, my_endpoint, len);

    void *sink = test_context_socket (ZMQ_PULL);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sink, my_endpoint));

    //  Set up poller
    void *poller = zmq_poller_new ();

    // register sink
    TEST_ASSERT_SUCCESS_ERRNO (zmq_poller_add (poller, sink, sink, ZMQ_POLLIN));

    //  Send a message
    const char *vent_sink_msg = "H";
    send_string_expect_success (vent, vent_sink_msg, 0);

    //  We expect a message only on the sink
    zmq_poller_event_t event;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_poller_wait (poller, &event, -1));
    TEST_ASSERT_EQUAL_PTR (sink, event.socket);
    TEST_ASSERT_EQUAL_PTR (sink, event.user_data);
    recv_string_expect_success (sink, vent_sink_msg, 0);

    //  We expect timed out
    TEST_ASSERT_FAILURE_ERRNO (EAGAIN, zmq_poller_wait (poller, &event, 0));

    //  Stop polling sink
    TEST_ASSERT_SUCCESS_ERRNO (zmq_poller_remove (poller, sink));

    //  Clean up
    test_context_socket_close (vent);
    test_context_socket_close (sink);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_poller_destroy (&poller));
}

void test_poll_fd ()
{
    //  Create sockets
    void *vent = test_context_socket (ZMQ_PUSH);

    size_t len = MAX_SOCKET_STRING;
    char my_endpoint[MAX_SOCKET_STRING];
    bind_loopback_ipv4 (vent, my_endpoint, len);

    void *bowl = test_context_socket (ZMQ_PULL);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (bowl, my_endpoint));

    //  Set up poller
    void *poller = zmq_poller_new ();

    //  Check we can poll an FD
    const fd_t fd = get_fd (bowl);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_poller_add_fd (poller, fd, bowl, ZMQ_POLLIN));

    zmq_poller_event_t event;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_poller_wait (poller, &event, 500));
    TEST_ASSERT_NULL (event.socket);
    TEST_ASSERT_EQUAL (fd, event.fd);
    TEST_ASSERT_EQUAL_PTR (bowl, event.user_data);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_poller_remove_fd (poller, fd));

    //  Clean up
    test_context_socket_close (vent);
    test_context_socket_close (bowl);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_poller_destroy (&poller));
}

void test_poll_client_server ()
{
#if defined(ZMQ_SERVER) && defined(ZMQ_CLIENT)
    //  Create sockets
    void *server = test_context_socket (ZMQ_SERVER);

    size_t len = MAX_SOCKET_STRING;
    char my_endpoint[MAX_SOCKET_STRING];
    bind_loopback_ipv4 (server, my_endpoint, len);

    void *client = test_context_socket (ZMQ_CLIENT);

    //  Set up poller
    void *poller = zmq_poller_new ();

    //  Polling on thread safe sockets
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_poller_add (poller, server, NULL, ZMQ_POLLIN));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (client, my_endpoint));

    const char *client_server_msg = "I";
    send_string_expect_success (client, client_server_msg, 0);

    zmq_poller_event_t event;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_poller_wait (poller, &event, 500));
    TEST_ASSERT_EQUAL_PTR (server, event.socket);
    TEST_ASSERT_NULL (event.user_data);
    recv_string_expect_success (server, client_server_msg, 0);

    //  Polling on pollout
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_poller_modify (poller, server, ZMQ_POLLOUT | ZMQ_POLLIN));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_poller_wait (poller, &event, 0));
    TEST_ASSERT_EQUAL_PTR (server, event.socket);
    TEST_ASSERT_NULL (event.user_data);
    TEST_ASSERT_EQUAL_INT (ZMQ_POLLOUT, event.events);

    //  Stop polling server
    TEST_ASSERT_SUCCESS_ERRNO (zmq_poller_remove (poller, server));

    //  Clean up
    test_context_socket_close (server);
    test_context_socket_close (client);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_poller_destroy (&poller));
#endif
}

int main (void)
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_null_poller_pointers_destroy_direct);
    RUN_TEST (test_null_poller_pointers_destroy_indirect);
    RUN_TEST (test_null_poller_pointers_add_direct);
    RUN_TEST (test_null_poller_pointers_add_indirect);
    RUN_TEST (test_null_poller_pointers_modify_direct);
    RUN_TEST (test_null_poller_pointers_modify_indirect);
    RUN_TEST (test_null_poller_pointers_remove_direct);
    RUN_TEST (test_null_poller_pointers_remove_indirect);
    RUN_TEST (test_null_poller_pointers_add_fd_direct);
    RUN_TEST (test_null_poller_pointers_add_fd_indirect);
    RUN_TEST (test_null_poller_pointers_modify_fd_direct);
    RUN_TEST (test_null_poller_pointers_modify_fd_indirect);
    RUN_TEST (test_null_poller_pointers_remove_fd_direct);
    RUN_TEST (test_null_poller_pointers_remove_fd_indirect);
    RUN_TEST (test_null_poller_pointers_wait_direct);
    RUN_TEST (test_null_poller_pointers_wait_indirect);
    RUN_TEST (test_null_poller_pointers_wait_all_direct);
    RUN_TEST (test_null_poller_pointers_wait_all_indirect);
    RUN_TEST (test_null_poller_pointer_poller_fd);

    RUN_TEST (test_null_socket_pointers);

    RUN_TEST (test_call_poller_wait_null_event_fails);
    RUN_TEST (test_call_poller_wait_all_null_event_fails_event_count_nonzero);
    RUN_TEST (test_call_poller_wait_all_null_event_fails_event_count_zero);

    RUN_TEST (test_call_poller_add_twice_fails);
    RUN_TEST (test_call_poller_remove_unregistered_fails);
    RUN_TEST (test_call_poller_modify_unregistered_fails);
    RUN_TEST (test_call_poller_add_no_events);
    RUN_TEST (test_call_poller_modify_no_events);
    RUN_TEST (test_call_poller_add_fd_twice_fails);
    RUN_TEST (test_call_poller_remove_fd_unregistered_fails);
    RUN_TEST (test_call_poller_modify_fd_unregistered_fails);
    RUN_TEST (test_call_poller_add_invalid_events_fails);
    RUN_TEST (test_call_poller_modify_invalid_events_fails);
    RUN_TEST (test_call_poller_add_fd_invalid_events_fails);
    RUN_TEST (test_call_poller_modify_fd_invalid_events_fails);

    RUN_TEST (test_call_poller_wait_empty_with_timeout_fails);
    RUN_TEST (test_call_poller_wait_empty_without_timeout_fails);
    RUN_TEST (test_call_poller_wait_all_empty_negative_count_fails);
    RUN_TEST (test_call_poller_wait_all_empty_without_timeout_fails);
    RUN_TEST (test_call_poller_wait_all_empty_with_timeout_fails);

    RUN_TEST (test_call_poller_fd_no_signaler);
    RUN_TEST (test_call_poller_fd);

    RUN_TEST (test_poll_basic);
    RUN_TEST (test_poll_fd);
    RUN_TEST (test_poll_client_server);

    return UNITY_END ();
}
