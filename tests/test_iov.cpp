/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

#include <stdlib.h>
#include <string.h>

SETUP_TEARDOWN_TESTCONTEXT

// XSI vector I/O
#if defined ZMQ_HAVE_UIO
#include <sys/uio.h>
#else
struct iovec
{
    void *iov_base;
    size_t iov_len;
};
#endif

static void do_check (void *sb_, void *sc_, size_t msg_size_)
{
    TEST_ASSERT_NOT_NULL (sb_);
    TEST_ASSERT_NOT_NULL (sc_);
    TEST_ASSERT_GREATER_THAN (0, msg_size_);

    const char msg_val = '1';
    const int num_messages = 10;
    size_t send_count, recv_count;

    send_count = recv_count = num_messages;

    char *ref_msg = static_cast<char *> (malloc (msg_size_));
    TEST_ASSERT_NOT_NULL (ref_msg);
    memset (ref_msg, msg_val, msg_size_);

    // zmq_sendiov(3) as a single multi-part send
    struct iovec send_iov[num_messages];
    char *buf = static_cast<char *> (malloc (msg_size_ * num_messages));

    for (int i = 0; i < num_messages; i++) {
        send_iov[i].iov_base = &buf[i * msg_size_];
        send_iov[i].iov_len = msg_size_;
        memcpy (send_iov[i].iov_base, ref_msg, msg_size_);

        // TODO: this assertion only checks if memcpy behaves as expected... remove this or assert something else?
        TEST_ASSERT_EQUAL_HEX8_ARRAY (ref_msg, send_iov[i].iov_base, msg_size_);
    }

    // Test errors - zmq_recviov - null socket
    TEST_ASSERT_FAILURE_ERRNO (
      ENOTSOCK, zmq_sendiov (NULL, send_iov, send_count, ZMQ_SNDMORE));
    // Test errors - zmq_recviov - invalid send count
    TEST_ASSERT_FAILURE_ERRNO (EINVAL, zmq_sendiov (sc_, send_iov, 0, 0));
    // Test errors - zmq_recviov - null iovec
    TEST_ASSERT_FAILURE_ERRNO (EINVAL, zmq_sendiov (sc_, NULL, send_count, 0));

    // Test success

    // The zmq_sendiov(3) API method does not follow the same semantics as
    // zmq_recviov(3); the latter returns the count of messages sent, rightly
    // so, whilst the former sends the number of bytes successfully sent from
    // the last message, which does not hold much sense from a batch send
    // perspective; hence the assert checks if the result is same as msg_size.
    TEST_ASSERT_EQUAL_INT (
      (int) msg_size_, TEST_ASSERT_SUCCESS_ERRNO (
                         zmq_sendiov (sc_, send_iov, send_count, ZMQ_SNDMORE)));

    // zmq_recviov(3) single-shot
    struct iovec recv_iov[num_messages];

    // Test errors - zmq_recviov - null socket
    TEST_ASSERT_FAILURE_ERRNO (ENOTSOCK,
                               zmq_recviov (NULL, recv_iov, &recv_count, 0));
    // Test error - zmq_recviov - invalid receive count
    TEST_ASSERT_FAILURE_ERRNO (EINVAL, zmq_recviov (sb_, recv_iov, NULL, 0));
    size_t invalid_recv_count = 0;
    TEST_ASSERT_FAILURE_ERRNO (
      EINVAL, zmq_recviov (sb_, recv_iov, &invalid_recv_count, 0));
    // Test error - zmq_recviov - null iovec
    TEST_ASSERT_FAILURE_ERRNO (EINVAL, zmq_recviov (sb_, NULL, &recv_count, 0));

    // Test success
    TEST_ASSERT_EQUAL_INT (
      num_messages,
      TEST_ASSERT_SUCCESS_ERRNO (zmq_recviov (sb_, recv_iov, &recv_count, 0)));

    for (int i = 0; i < num_messages; i++) {
        TEST_ASSERT_NOT_NULL (recv_iov[i].iov_base);
        TEST_ASSERT_EQUAL_STRING_LEN (ref_msg, recv_iov[i].iov_base, msg_size_);
        free (recv_iov[i].iov_base);
    }

    TEST_ASSERT_EQUAL_INT (send_count, recv_count);
    free (ref_msg);
    free (buf);
}

void test_iov ()
{
    void *sb = test_context_socket (ZMQ_PULL);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (sb, "inproc://a"));

    msleep (SETTLE_TIME);

    void *sc = test_context_socket (ZMQ_PUSH);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc, "inproc://a"));

    // message bigger than VSM max
    do_check (sb, sc, 100);

    // message smaller than VSM max
    do_check (sb, sc, 10);

    test_context_socket_close (sc);
    test_context_socket_close (sb);
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_iov);
    return UNITY_END ();
}
