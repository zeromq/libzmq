/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

#include <stdlib.h>
#include <string.h>
#include <string>

#if !defined ZMQ_HAVE_WINDOWS
#include <netdb.h>
#endif

SETUP_TEARDOWN_TESTCONTEXT

void str_send_to (void *s_, const char *content_, const char *address_)
{
    send_string_expect_success (s_, address_, ZMQ_SNDMORE);
    send_string_expect_success (s_, content_, 0);
}

static void assert_raw_datagram_received (void *s_,
                                          const char *content_,
                                          const char *address_)
{
    char received_address[64] = {0};
    char received_content[64] = {0};

    TEST_ASSERT_EQUAL_INT (strlen (address_) + 1,
      zmq_recv (s_, received_address, sizeof received_address, 0));
    TEST_ASSERT_EQUAL_STRING (address_, received_address);
    TEST_ASSERT_EQUAL_INT (strlen (content_),
      zmq_recv (s_, received_content, sizeof received_content, 0));
    TEST_ASSERT_EQUAL_STRING (content_, received_content);
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

void test_invalid_raw_addresses_are_dropped ()
{
    static const char *const invalid_addresses[] = {
      "localhost:5559", "not-an-address:5559", "2001:db8::1:5559",
      ":5559", "255.255.255.255:5559"};

    void *sender = test_context_socket (ZMQ_DGRAM);
    void *listener = test_context_socket (ZMQ_DGRAM);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (listener, ENDPOINT_4));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (sender, ENDPOINT_5));

    int timeout = 250;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (listener, ZMQ_RCVTIMEO, &timeout, sizeof (timeout)));

    char buffer[64];
    for (size_t i = 0;
         i < sizeof (invalid_addresses) / sizeof (invalid_addresses[0]); ++i) {
        str_send_to (sender, test_question, invalid_addresses[i]);
        TEST_ASSERT_FAILURE_ERRNO (
          EAGAIN, zmq_recv (listener, buffer, sizeof buffer, 0));
    }

    str_send_to (sender, test_answer, "127.0.0.1:5559");
    assert_raw_datagram_received (listener, test_answer, "127.0.0.1:5560");

    test_context_socket_close (sender);
    test_context_socket_close (listener);
}

void test_legacy_numeric_addresses ()
{
    static const char *const legacy_addresses[] = {
      "127.1", "0177.0.0.1", "0x7f000001"};
    bool supported[sizeof (legacy_addresses) / sizeof (legacy_addresses[0])];
    size_t supported_count = 0;
    void *sender = test_context_socket (ZMQ_DGRAM);
    void *listener = test_context_socket (ZMQ_DGRAM);

    for (size_t i = 0;
         i < sizeof (legacy_addresses) / sizeof (legacy_addresses[0]); ++i) {
        struct addrinfo hints;
        memset (&hints, 0, sizeof hints);
        hints.ai_family = AF_INET;
        hints.ai_flags = AI_NUMERICHOST;

        struct addrinfo *result = NULL;
        supported[i] =
          getaddrinfo (legacy_addresses[i], NULL, &hints, &result) == 0
          && result != NULL && result->ai_addr != NULL
          && result->ai_family == AF_INET
          && static_cast<size_t> (result->ai_addrlen)
               >= sizeof (struct sockaddr_in)
          && reinterpret_cast<struct sockaddr_in *> (result->ai_addr)
               ->sin_addr.s_addr
               == htonl (INADDR_LOOPBACK);
        if (result != NULL)
            freeaddrinfo (result);
        if (supported[i])
            ++supported_count;
    }

    if (supported_count == 0) {
        test_context_socket_close (sender);
        test_context_socket_close (listener);
        TEST_IGNORE_MESSAGE (
          "the platform numeric resolver accepts no tested legacy IPv4 form");
    }

    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (listener, ENDPOINT_4));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (sender, ENDPOINT_5));

    int timeout = 1000;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (listener, ZMQ_RCVTIMEO, &timeout, sizeof (timeout)));

    for (size_t i = 0;
         i < sizeof (legacy_addresses) / sizeof (legacy_addresses[0]); ++i) {
        if (!supported[i])
            continue;

        const std::string destination =
          std::string (legacy_addresses[i]) + ":5559";
        str_send_to (sender, test_question, destination.c_str ());
        assert_raw_datagram_received (listener, test_question,
                                      "127.0.0.1:5560");
    }

    test_context_socket_close (sender);
    test_context_socket_close (listener);
}

int main (void)
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_connect_fails);
    RUN_TEST (test_roundtrip);
    RUN_TEST (test_invalid_raw_addresses_are_dropped);
    RUN_TEST (test_legacy_numeric_addresses);
    return UNITY_END ();
}
