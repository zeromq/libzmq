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

#if defined(_MSC_VER) && _MSC_VER <= 1800
#define snprintf _snprintf
#endif

int test_assert_success_message_errno_helper (int rc_,
                                              const char *msg_,
                                              const char *expr_);

int test_assert_success_message_raw_errno_helper (int rc_,
                                                  const char *msg_,
                                                  const char *expr_);

int test_assert_failure_message_raw_errno_helper (int rc_,
                                                  int expected_errno_,
                                                  const char *msg_,
                                                  const char *expr_);

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

void send_string_expect_success (void *socket_, const char *str_, int flags_);

void recv_string_expect_success (void *socket_, const char *str_, int flags_);

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

#define MAX_TEST_SOCKETS 128

void setup_test_context ();

void *get_test_context ();

void teardown_test_context ();

void *test_context_socket (int type_);

void *test_context_socket_close (void *socket_);

void *test_context_socket_close_zero_linger (void *socket_);

void test_bind (void *socket_,
                const char *bind_address_,
                char *my_endpoint_,
                size_t len_);

void bind_loopback (void *socket_, int ipv6_, char *my_endpoint_, size_t len_);

typedef void (*bind_function_t) (void *socket_,
                                 char *my_endpoint_,
                                 size_t len_);

void bind_loopback_ipv4 (void *socket_, char *my_endpoint_, size_t len_);

void bind_loopback_ipv6 (void *socket_, char *my_endpoint_, size_t len_);

void bind_loopback_ipc (void *socket_, char *my_endpoint_, size_t len_);

void bind_loopback_tipc (void *socket_, char *my_endpoint_, size_t len_);

#if !defined(ZMQ_HAVE_WINDOWS) && !defined(ZMQ_HAVE_GNU)
// utility function to create a random IPC endpoint, similar to what a ipc://*
// wildcard binding does, but in a way it can be reused for multiple binds
void make_random_ipc_endpoint (char *out_endpoint_);
#endif
