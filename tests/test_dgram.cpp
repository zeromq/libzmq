/*
    Copyright (c) 2016 Contributors as noted in the AUTHORS file

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

#include <stdlib.h>
#include <string.h>

SETUP_TEARDOWN_TESTCONTEXT

void str_send_to (void *s_, const char *content_, const char *address_)
{
    send_string_expect_success (s_, address_, ZMQ_SNDMORE);
    send_string_expect_success (s_, content_, 0);
}

void str_recv_from (void *s_, char **ptr_content_, char **ptr_address_)
{
    *ptr_address_ = s_recv (s_);
    TEST_ASSERT_NOT_NULL (ptr_address_);

    *ptr_content_ = s_recv (s_);
    TEST_ASSERT_NOT_NULL (ptr_content_);
}

static const char test_question[] = "Is someone there ?";
static const char test_answer[] = "Yes, there is !";

void test_connect_fails ()
{
    void *socket = test_context_socket (ZMQ_DGRAM);

    //  Connecting dgram should fail
    TEST_ASSERT_FAILURE_ERRNO (ENOCOMPATPROTO,
                               zmq_connect (socket, ENDPOINT_4));

    test_context_socket_close (socket);
}

void test_roundtrip ()
{
    char *message_string;
    char *address;

    void *sender = test_context_socket (ZMQ_DGRAM);
    void *listener = test_context_socket (ZMQ_DGRAM);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (listener, ENDPOINT_4));

    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (sender, ENDPOINT_5));

    str_send_to (sender, test_question, strrchr (ENDPOINT_4, '/') + 1);

    str_recv_from (listener, &message_string, &address);
    TEST_ASSERT_EQUAL_STRING (test_question, message_string);
    TEST_ASSERT_EQUAL_STRING (strrchr (ENDPOINT_5, '/') + 1, address);
    free (message_string);

    str_send_to (listener, test_answer, address);
    free (address);

    str_recv_from (sender, &message_string, &address);
    TEST_ASSERT_EQUAL_STRING (test_answer, message_string);
    TEST_ASSERT_EQUAL_STRING (strrchr (ENDPOINT_4, '/') + 1, address);
    free (message_string);
    free (address);

    test_context_socket_close (sender);
    test_context_socket_close (listener);
}

int main (void)
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_connect_fails);
    RUN_TEST (test_roundtrip);
    return UNITY_END ();
}
