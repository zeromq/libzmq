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
