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

#include "testutil.hpp"

#include <unity.h>

#include <string.h>
#include <stdio.h>

#if defined(_MSC_VER) && _MSC_VER <= 1800
#define snprintf _snprintf
#endif

int test_assert_success_message_errno_helper (int rc_,
                                              const char *msg_,
                                              const char *expr_)
{
    if (rc_ == -1) {
        char buffer[512];
        buffer[sizeof (buffer) - 1] =
          0; // to ensure defined behavior with VC++ <= 2013
        snprintf (buffer, sizeof (buffer) - 1,
                  "%s failed%s%s%s, errno = %i (%s)", expr_,
                  msg_ ? " (additional info: " : "", msg_ ? msg_ : "",
                  msg_ ? ")" : "", zmq_errno (), zmq_strerror (zmq_errno ()));
        TEST_FAIL_MESSAGE (buffer);
    }
    return rc_;
}

int test_assert_success_message_raw_errno_helper (int rc_,
                                                  const char *msg_,
                                                  const char *expr_)
{
    if (rc_ == -1) {
#if defined ZMQ_HAVE_WINDOWS
        int current_errno = WSAGetLastError ();
#else
        int current_errno = errno;
#endif

        char buffer[512];
        buffer[sizeof (buffer) - 1] =
          0; // to ensure defined behavior with VC++ <= 2013
        snprintf (buffer, sizeof (buffer) - 1, "%s failed%s%s%s, errno = %i",
                  expr_, msg_ ? " (additional info: " : "", msg_ ? msg_ : "",
                  msg_ ? ")" : "", current_errno);
        TEST_FAIL_MESSAGE (buffer);
    }
    return rc_;
}

int test_assert_failure_message_raw_errno_helper (int rc_,
                                                  int expected_errno_,
                                                  const char *msg_,
                                                  const char *expr_)
{
    char buffer[512];
    buffer[sizeof (buffer) - 1] =
      0; // to ensure defined behavior with VC++ <= 2013
    if (rc_ != -1) {
        snprintf (buffer, sizeof (buffer) - 1,
                  "%s was unexpectedly successful%s%s%s, expected "
                  "errno = %i, actual return value = %i",
                  expr_, msg_ ? " (additional info: " : "", msg_ ? msg_ : "",
                  msg_ ? ")" : "", expected_errno_, rc_);
        TEST_FAIL_MESSAGE (buffer);
    } else {
#if defined ZMQ_HAVE_WINDOWS
        int current_errno = WSAGetLastError ();
#else
        int current_errno = errno;
#endif
        if (current_errno != expected_errno_) {
            snprintf (buffer, sizeof (buffer) - 1,
                      "%s failed with an unexpected error%s%s%s, expected "
                      "errno = %i, actual errno = %i",
                      expr_, msg_ ? " (additional info: " : "",
                      msg_ ? msg_ : "", msg_ ? ")" : "", expected_errno_,
                      current_errno);
            TEST_FAIL_MESSAGE (buffer);
        }
    }
    return rc_;
}

#define TEST_ASSERT_SUCCESS_MESSAGE_ERRNO(expr, msg)                           \
    test_assert_success_message_errno_helper (expr, msg, #expr)

#define TEST_ASSERT_SUCCESS_ERRNO(expr)                                        \
    test_assert_success_message_errno_helper (expr, NULL, #expr)

#define TEST_ASSERT_SUCCESS_RAW_ERRNO(expr)                                    \
    test_assert_success_message_raw_errno_helper (expr, NULL, #expr)

#define TEST_ASSERT_FAILURE_RAW_ERRNO(error_code, expr)                        \
    test_assert_failure_message_raw_errno_helper (expr, error_code, NULL, #expr)

#define TEST_ASSERT_FAILURE_ERRNO(error_code, expr)                            \
    {                                                                          \
        int _rc = (expr);                                                      \
        TEST_ASSERT_EQUAL_INT (-1, _rc);                                       \
        TEST_ASSERT_EQUAL_INT (error_code, errno);                             \
    }

void send_string_expect_success (void *socket_, const char *str_, int flags_)
{
    const size_t len = str_ ? strlen (str_) : 0;
    const int rc = zmq_send (socket_, str_, len, flags_);
    TEST_ASSERT_EQUAL_INT ((int) len, rc);
}

void recv_string_expect_success (void *socket_, const char *str_, int flags_)
{
    const size_t len = str_ ? strlen (str_) : 0;
    char buffer[255];
    TEST_ASSERT_LESS_OR_EQUAL_MESSAGE (sizeof (buffer), len,
                                       "recv_string_expect_success cannot be "
                                       "used for strings longer than 255 "
                                       "characters");

    const int rc = TEST_ASSERT_SUCCESS_ERRNO (
      zmq_recv (socket_, buffer, sizeof (buffer), flags_));
    TEST_ASSERT_EQUAL_INT ((int) len, rc);
    if (str_)
        TEST_ASSERT_EQUAL_STRING_LEN (str_, buffer, len);
}

template <size_t SIZE>
void send_array_expect_success (void *socket_,
                                const uint8_t (&array_)[SIZE],
                                int flags_)
{
    const int rc = zmq_send (socket_, array_, SIZE, flags_);
    TEST_ASSERT_EQUAL_INT (static_cast<int> (SIZE), rc);
}

template <size_t SIZE>
void recv_array_expect_success (void *socket_,
                                const uint8_t (&array_)[SIZE],
                                int flags_)
{
    char buffer[255];
    TEST_ASSERT_LESS_OR_EQUAL_MESSAGE (sizeof (buffer), SIZE,
                                       "recv_string_expect_success cannot be "
                                       "used for strings longer than 255 "
                                       "characters");

    const int rc = TEST_ASSERT_SUCCESS_ERRNO (
      zmq_recv (socket_, buffer, sizeof (buffer), flags_));
    TEST_ASSERT_EQUAL_INT (static_cast<int> (SIZE), rc);
    TEST_ASSERT_EQUAL_UINT8_ARRAY (array_, buffer, SIZE);
}

// do not call from tests directly, use setup_test_context, get_test_context and teardown_test_context only
void *internal_manage_test_context (bool init_, bool clear_)
{
    static void *test_context = NULL;
    if (clear_) {
        TEST_ASSERT_NOT_NULL (test_context);
        TEST_ASSERT_SUCCESS_ERRNO (zmq_ctx_term (test_context));
        test_context = NULL;
    } else {
        if (init_) {
            TEST_ASSERT_NULL (test_context);
            test_context = zmq_ctx_new ();
            TEST_ASSERT_NOT_NULL (test_context);
        }
    }
    return test_context;
}

#define MAX_TEST_SOCKETS 128

void internal_manage_test_sockets (void *socket_, bool add_)
{
    static void *test_sockets[MAX_TEST_SOCKETS];
    static size_t test_socket_count = 0;
    if (!socket_) {
        assert (!add_);

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
        if (add_) {
            ++test_socket_count;
            TEST_ASSERT_LESS_THAN_MESSAGE (MAX_TEST_SOCKETS, test_socket_count,
                                           "MAX_TEST_SOCKETS must be "
                                           "increased, or you cannot use the "
                                           "test context");
            test_sockets[test_socket_count - 1] = socket_;
        } else {
            bool found = false;
            for (size_t i = 0; i < test_socket_count; ++i) {
                if (test_sockets[i] == socket_) {
                    found = true;
                }
                if (found) {
                    if (i < test_socket_count)
                        test_sockets[i] = test_sockets[i + 1];
                }
            }
            TEST_ASSERT_TRUE_MESSAGE (found,
                                      "Attempted to close a socket that was "
                                      "not created by test_context_socket");
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

void *test_context_socket (int type_)
{
    void *const socket = zmq_socket (get_test_context (), type_);
    TEST_ASSERT_NOT_NULL (socket);
    internal_manage_test_sockets (socket, true);
    return socket;
}

void *test_context_socket_close (void *socket_)
{
    TEST_ASSERT_SUCCESS_ERRNO (zmq_close (socket_));
    internal_manage_test_sockets (socket_, false);
    return socket_;
}

void *test_context_socket_close_zero_linger (void *socket_)
{
    const int linger = 0;
    int rc = zmq_setsockopt (socket_, ZMQ_LINGER, &linger, sizeof (linger));
    TEST_ASSERT_TRUE (rc == 0 || zmq_errno () == ETERM);
    return test_context_socket_close (socket_);
}

void test_bind (void *socket_,
                const char *bind_address_,
                char *my_endpoint_,
                size_t len_)
{
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (socket_, bind_address_));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (socket_, ZMQ_LAST_ENDPOINT, my_endpoint_, &len_));
}

void bind_loopback (void *socket_, int ipv6_, char *my_endpoint_, size_t len_)
{
    if (ipv6_ && !is_ipv6_available ()) {
        TEST_IGNORE_MESSAGE ("ipv6 is not available");
    }

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (socket_, ZMQ_IPV6, &ipv6_, sizeof (int)));

    test_bind (socket_, ipv6_ ? "tcp://[::1]:*" : "tcp://127.0.0.1:*",
               my_endpoint_, len_);
}

typedef void (*bind_function_t) (void *socket_,
                                 char *my_endpoint_,
                                 size_t len_);

void bind_loopback_ipv4 (void *socket_, char *my_endpoint_, size_t len_)
{
    bind_loopback (socket_, false, my_endpoint_, len_);
}

void bind_loopback_ipv6 (void *socket_, char *my_endpoint_, size_t len_)
{
    bind_loopback (socket_, true, my_endpoint_, len_);
}

void bind_loopback_ipc (void *socket_, char *my_endpoint_, size_t len_)
{
    if (!zmq_has ("ipc")) {
        TEST_IGNORE_MESSAGE ("ipc is not available");
    }

    test_bind (socket_, "ipc://*", my_endpoint_, len_);
}

void bind_loopback_tipc (void *socket_, char *my_endpoint_, size_t len_)
{
    if (!is_tipc_available ()) {
        TEST_IGNORE_MESSAGE ("tipc is not available");
    }

    test_bind (socket_, "tipc://<*>", my_endpoint_, len_);
}

#if !defined(ZMQ_HAVE_WINDOWS) && !defined(ZMQ_HAVE_GNU)
// utility function to create a random IPC endpoint, similar to what a ipc://*
// wildcard binding does, but in a way it can be reused for multiple binds
void make_random_ipc_endpoint (char *out_endpoint_)
{
    char random_file[16];
    strcpy (random_file, "tmpXXXXXX");

#ifdef HAVE_MKDTEMP
    TEST_ASSERT_TRUE (mkdtemp (random_file));
    strcat (random_file, "/ipc");
#else
    int fd = mkstemp (random_file);
    TEST_ASSERT_TRUE (fd != -1);
    close (fd);
#endif

    strcpy (out_endpoint_, "ipc://");
    strcat (out_endpoint_, random_file);
}
#endif
