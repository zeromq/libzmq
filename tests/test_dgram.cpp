/* SPDX-License-Identifier: MPL-2.0 */

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
