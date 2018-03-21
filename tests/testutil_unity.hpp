#pragma once

/*
Copyright (c) 2018 Contributors as noted in the AUTHORS file

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

#include "../include/zmq.h"

#include <unity.h>

#include <string.h>
#include <stdio.h>

#if defined(_MSC_VER) && _MSC_VER <= 1800
#define snprintf _snprintf
#endif

int test_assert_success_message_errno_helper (int rc,
                                              const char *msg,
                                              const char *expr)
{
    if (rc == -1) {
        char buffer[512];
        buffer[sizeof (buffer) - 1] =
          0; // to ensure defined behavior with VC++ <= 2013
        snprintf (buffer, sizeof (buffer) - 1,
                  "%s failed%s%s%s, errno = %i (%s)", expr,
                  msg ? " (additional info: " : "", msg ? msg : "",
                  msg ? ")" : "", zmq_errno (), zmq_strerror (zmq_errno ()));
        TEST_FAIL_MESSAGE (buffer);
    }
    return rc;
}

#define TEST_ASSERT_SUCCESS_MESSAGE_ERRNO(expr, msg)                           \
    test_assert_success_message_errno_helper (expr, msg, #expr)

#define TEST_ASSERT_SUCCESS_ERRNO(expr)                                        \
    test_assert_success_message_errno_helper (expr, NULL, #expr)

#define TEST_ASSERT_FAILURE_ERRNO(error_code, expr)                            \
    {                                                                          \
        int rc = (expr);                                                       \
        TEST_ASSERT_EQUAL_INT (-1, rc);                                        \
        TEST_ASSERT_EQUAL_INT (error_code, errno);                             \
    }

void send_string_expect_success (void *socket, const char *str, int flags)
{
    const size_t len = str ? strlen (str) : 0;
    const int rc = zmq_send (socket, str, len, flags);
    TEST_ASSERT_EQUAL_INT ((int) len, rc);
}

void recv_string_expect_success (void *socket, const char *str, int flags)
{
    const size_t len = str ? strlen (str) : 0;
    char buffer[255];
    TEST_ASSERT_LESS_OR_EQUAL_MESSAGE (sizeof (buffer), len,
                                       "recv_string_expect_success cannot be "
                                       "used for strings longer than 255 "
                                       "characters");

    const int rc =
      TEST_ASSERT_SUCCESS_ERRNO (zmq_recv (socket, buffer, sizeof (buffer), 0));
    TEST_ASSERT_EQUAL_INT ((int) len, rc);
    if (str)
        TEST_ASSERT_EQUAL_STRING_LEN (str, buffer, len);
}

// do not call from tests directly, use setup_test_context, get_test_context and teardown_test_context only
void *internal_manage_test_context (bool init, bool clear)
{
    static void *test_context = NULL;
    if (clear) {
        TEST_ASSERT_NOT_NULL (test_context);
        TEST_ASSERT_SUCCESS_ERRNO (zmq_ctx_term (test_context));
        test_context = NULL;
    } else {
        if (init) {
            TEST_ASSERT_NULL (test_context);
            test_context = zmq_ctx_new ();
            TEST_ASSERT_NOT_NULL (test_context);
        }
    }
    return test_context;
}

#define MAX_TEST_SOCKETS 128

void internal_manage_test_sockets (void *socket, bool add)
{
    static void *test_sockets[MAX_TEST_SOCKETS];
    static size_t test_socket_count = 0;
    if (!socket) {
        assert (!add);

        // force-close all sockets
        if (test_socket_count) {
            for (size_t i = 0; i < test_socket_count; ++i) {
                close_zero_linger (test_sockets[i]);
            }
            fprintf (stderr,
                     "WARNING: Forced closure of %i sockets, this is an "
                     "implementation error unless the test case failed\n",
                     (int) test_socket_count);
            test_socket_count = 0;
        }
    } else {
        if (add) {
            ++test_socket_count;
            TEST_ASSERT_LESS_THAN_MESSAGE (MAX_TEST_SOCKETS, test_socket_count,
                                           "MAX_TEST_SOCKETS must be "
                                           "increased, or you cannot use the "
                                           "test context");
            test_sockets[test_socket_count - 1] = socket;
        } else {
            bool found = false;
            for (size_t i = 0; i < test_socket_count; ++i) {
                if (test_sockets[i] == socket) {
                    found = true;
                }
                if (found) {
                    if (i < test_socket_count)
                        test_sockets[i] = test_sockets[i + 1];
                }
            }
            TEST_ASSERT_TRUE (found);
            --test_socket_count;
        }
    }
}

void setup_test_context ()
{
    internal_manage_test_context (true, false);
}

void *get_test_context ()
{
    return internal_manage_test_context (false, false);
}

void teardown_test_context ()
{
    // this condition allows an explicit call to teardown_test_context from a
    // test. if this is never used, it should probably be removed, to detect
    // misuses
    if (get_test_context ()) {
        internal_manage_test_sockets (NULL, false);
        internal_manage_test_context (false, true);
    }
}

void *test_context_socket (int type)
{
    void *const socket = zmq_socket (get_test_context (), type);
    TEST_ASSERT_NOT_NULL (socket);
    internal_manage_test_sockets (socket, true);
    return socket;
}

void *test_context_socket_close (void *socket)
{
    TEST_ASSERT_SUCCESS_ERRNO (zmq_close (socket));
    internal_manage_test_sockets (socket, false);
    return socket;
}

void bind_loopback (void *socket, int ipv6, char *my_endpoint, size_t len)
{
    if (ipv6 && !is_ipv6_available ()) {
        TEST_IGNORE_MESSAGE ("ipv6 is not available");
    }

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (socket, ZMQ_IPV6, &ipv6, sizeof (int)));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_bind (socket, ipv6 ? "tcp://[::1]:*" : "tcp://127.0.0.1:*"));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (socket, ZMQ_LAST_ENDPOINT, my_endpoint, &len));
}

void bind_loopback_ipv4 (void *socket, char *my_endpoint, size_t len)
{
    bind_loopback (socket, false, my_endpoint, len);
}
