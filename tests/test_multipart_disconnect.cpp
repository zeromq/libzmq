/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"
#include "testutil_monitoring.hpp"

#include <stdlib.h>
#include <string.h>

static void *released[2];
static void *monitor;

void setUp ()
{
    setup_test_context ();
    for (int i = 0; i != 2; ++i) {
        released[i] = zmq_atomic_counter_new ();
        TEST_ASSERT_NOT_NULL (released[i]);
    }
}

void tearDown ()
{
    // The I/O threads may run the callbacks during context termination.
    teardown_test_context ();
    for (int i = 0; i != 2; ++i)
        zmq_atomic_counter_destroy (&released[i]);
}

static void release_frame (void *data_, void *hint_)
{
    free (data_);
    zmq_atomic_counter_inc (hint_);
}

static void set_int_option (void *socket_, int option_, int value_)
{
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (socket_, option_, &value_, sizeof value_));
}

static void process_commands (void *socket_)
{
    int events;
    size_t size = sizeof events;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (socket_, ZMQ_EVENTS, &events, &size));
}

static void *publisher (char *endpoint_)
{
    void *pub = test_context_socket (ZMQ_PUB);
    set_int_option (pub, ZMQ_LINGER, 0);
    set_int_option (pub, ZMQ_SNDTIMEO, 2000);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_socket_monitor (
      pub, "inproc://multipart-monitor", ZMQ_EVENT_DISCONNECTED));
    monitor = test_context_socket (ZMQ_PAIR);
    set_int_option (monitor, ZMQ_LINGER, 0);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_connect (monitor, "inproc://multipart-monitor"));
    bind_loopback_ipv4 (pub, endpoint_, MAX_SOCKET_STRING);
    return pub;
}

static void expect_disconnect (void *pub_, void *disconnecting_ = NULL)
{
    int event = -1;
    for (int i = 0; i != 200; ++i) {
        if (disconnecting_)
            process_commands (disconnecting_);
        process_commands (pub_);
        event = get_monitor_event_with_timeout (monitor, NULL, NULL, 10);
        if (event != -1)
            break;
    }
    TEST_ASSERT_EQUAL_INT (ZMQ_EVENT_DISCONNECTED, event);
}

static void *subscriber (void *pub_, const char *endpoint_)
{
    void *sub = test_context_socket (ZMQ_SUB);
    set_int_option (sub, ZMQ_LINGER, 0);
    set_int_option (sub, ZMQ_RCVTIMEO, 10);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (sub, ZMQ_SUBSCRIBE, "", 0));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sub, endpoint_));
    // Verify that the subscription reached PUB before starting the multipart send.
    for (int i = 0; i != 200; ++i) {
        send_string_expect_success (pub_, "ready", 0);
        char ready[5];
        const int rc = zmq_recv (sub, ready, sizeof ready, 0);
        if (rc == 5 && memcmp (ready, "ready", 5) == 0)
            return sub;
        TEST_ASSERT_EQUAL_INT (-1, rc);
        TEST_ASSERT_EQUAL_INT (EAGAIN, zmq_errno ());
    }
    TEST_FAIL_MESSAGE ("subscription readiness deadline");
    return sub;
}

static int receive_payload (void *sub_, char *data_, size_t size_)
{
    for (int i = 0; i != 200; ++i) {
        const int rc = zmq_recv (sub_, data_, size_, 0);
        if (rc >= 0) {
            // A second subscriber readiness probe can also reach the first.
            if (rc == 5 && memcmp (data_, "ready", 5) == 0)
                continue;
            return rc;
        }
        TEST_ASSERT_EQUAL_INT (EAGAIN, zmq_errno ());
    }
    TEST_FAIL_MESSAGE ("message receive deadline");
    return -1;
}

static void expect_text (void *sub_, const char *expected_)
{
    char data[4096];
    TEST_ASSERT_EQUAL_INT (strlen (expected_),
                           receive_payload (sub_, data, sizeof data));
    TEST_ASSERT_EQUAL_STRING_LEN (expected_, data, strlen (expected_));
    int more;
    size_t size = sizeof more;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (sub_, ZMQ_RCVMORE, &more, &size));
    TEST_ASSERT_EQUAL_INT (0, more);
}

static void close_publisher (void *pub_)
{
    TEST_ASSERT_SUCCESS_ERRNO (zmq_socket_monitor (pub_, NULL, 0));
    test_context_socket_close (monitor);
    test_context_socket_close (pub_);
}

static void send_frame (void *pub_, int counter_, char value_, int flags_)
{
    char *data = static_cast<char *> (malloc (4096));
    TEST_ASSERT_NOT_NULL (data);
    memset (data, value_, 4096);
    zmq_msg_t msg;
    const int init_rc =
      zmq_msg_init_data (&msg, data, 4096, release_frame, released[counter_]);
    if (init_rc != 0)
        free (data);
    TEST_ASSERT_SUCCESS_ERRNO (init_rc);
    const int send_rc = zmq_msg_send (&msg, pub_, flags_);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg));
    TEST_ASSERT_EQUAL_INT (4096, send_rc);
}

static void expect_frame (void *sub_, char value_, int more_)
{
    char data[4096];
    TEST_ASSERT_EQUAL_INT (4096, receive_payload (sub_, data, sizeof data));
    for (size_t i = 0; i != sizeof data; ++i)
        TEST_ASSERT_EQUAL_INT (value_, data[i]);
    int more = -1;
    size_t size = sizeof more;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (sub_, ZMQ_RCVMORE, &more, &size));
    TEST_ASSERT_EQUAL_INT (more_, more);
}

static void expect_released (void *pub_, int counter_, int count_)
{
    for (int i = 0;
         i != 2000 && zmq_atomic_counter_value (released[counter_]) < count_;
         ++i) {
        int events;
        size_t size = sizeof events;
        // Drive termination commands without completing the multipart send.
        TEST_ASSERT_SUCCESS_ERRNO (
          zmq_getsockopt (pub_, ZMQ_EVENTS, &events, &size));
        msleep (1);
    }
    TEST_ASSERT_EQUAL_INT (count_,
                           zmq_atomic_counter_value (released[counter_]));
}

static void incomplete_disconnect (bool disconnect_)
{
    char endpoint[MAX_SOCKET_STRING];
    void *pub = publisher (endpoint);
    void *sub = subscriber (pub, endpoint);
    send_frame (pub, 0, 'a', ZMQ_SNDMORE);
    send_frame (pub, 1, 'b', ZMQ_SNDMORE);
    TEST_ASSERT_EQUAL_INT (0, zmq_atomic_counter_value (released[0]));
    TEST_ASSERT_EQUAL_INT (0, zmq_atomic_counter_value (released[1]));
    if (disconnect_)
        TEST_ASSERT_SUCCESS_ERRNO (zmq_disconnect (sub, endpoint));
    else
        test_context_socket_close (sub);
    expect_disconnect (pub, disconnect_ ? sub : NULL);
    expect_released (pub, 0, 1);
    expect_released (pub, 1, 1);
    if (disconnect_) {
        send_string_expect_success (pub, "tail", 0);
        test_context_socket_close (sub);
    }
    close_publisher (pub);
    teardown_test_context ();
    TEST_ASSERT_EQUAL_INT (1, zmq_atomic_counter_value (released[0]));
    TEST_ASSERT_EQUAL_INT (1, zmq_atomic_counter_value (released[1]));
}

void test_incomplete_close ()
{
    incomplete_disconnect (false);
}
void test_incomplete_disconnect ()
{
    incomplete_disconnect (true);
}

void test_complete_message ()
{
    char endpoint[MAX_SOCKET_STRING];
    void *pub = publisher (endpoint);
    void *sub = subscriber (pub, endpoint);
    send_frame (pub, 0, 'a', ZMQ_SNDMORE);
    send_frame (pub, 1, 'b', 0);
    expect_frame (sub, 'a', 1);
    expect_frame (sub, 'b', 0);
    expect_released (pub, 0, 1);
    expect_released (pub, 1, 1);
    test_context_socket_close (sub);
    close_publisher (pub);
    teardown_test_context ();
    TEST_ASSERT_EQUAL_INT (1, zmq_atomic_counter_value (released[0]));
    TEST_ASSERT_EQUAL_INT (1, zmq_atomic_counter_value (released[1]));
}

void test_remaining_subscriber ()
{
    char endpoint[MAX_SOCKET_STRING];
    void *pub = publisher (endpoint);
    void *departing = subscriber (pub, endpoint);
    void *remaining = subscriber (pub, endpoint);
    send_string_expect_success (pub, "before", 0);
    send_frame (pub, 0, 'a', ZMQ_SNDMORE);
    test_context_socket_close (departing);
    expect_disconnect (pub);
    // Process termination while the remaining subscriber still owns its reference.
    for (int i = 0; i != 20; ++i) {
        process_commands (pub);
        msleep (1);
    }
    TEST_ASSERT_EQUAL_INT (0, zmq_atomic_counter_value (released[0]));
    send_frame (pub, 1, 'b', 0);
    expect_text (remaining, "before");
    expect_frame (remaining, 'a', 1);
    expect_frame (remaining, 'b', 0);
    expect_released (pub, 0, 1);
    expect_released (pub, 1, 1);
    send_string_expect_success (pub, "next", 0);
    expect_text (remaining, "next");
    test_context_socket_close (remaining);
    close_publisher (pub);
    teardown_test_context ();
    TEST_ASSERT_EQUAL_INT (1, zmq_atomic_counter_value (released[0]));
    TEST_ASSERT_EQUAL_INT (1, zmq_atomic_counter_value (released[1]));
}

void test_repeated_disconnect ()
{
    char endpoint[MAX_SOCKET_STRING];
    void *pub = publisher (endpoint);
    for (int i = 0; i != 20; ++i) {
        void *sub = subscriber (pub, endpoint);
        send_frame (pub, 0, 'a', ZMQ_SNDMORE);
        test_context_socket_close (sub);
        expect_disconnect (pub);
        expect_released (pub, 0, i + 1);
        send_string_expect_success (pub, "tail", 0);
    }
    close_publisher (pub);
    teardown_test_context ();
    TEST_ASSERT_EQUAL_INT (20, zmq_atomic_counter_value (released[0]));
}

void test_publisher_shutdown ()
{
    char endpoint[MAX_SOCKET_STRING];
    void *pub = publisher (endpoint);
    void *sub = subscriber (pub, endpoint);
    send_frame (pub, 0, 'a', ZMQ_SNDMORE);
    close_publisher (pub);
    test_context_socket_close (sub);
    teardown_test_context ();
    TEST_ASSERT_EQUAL_INT (1, zmq_atomic_counter_value (released[0]));
}

int main ()
{
    setup_test_environment ();
    UNITY_BEGIN ();
    RUN_TEST (test_incomplete_close);
    RUN_TEST (test_incomplete_disconnect);
    RUN_TEST (test_complete_message);
    RUN_TEST (test_remaining_subscriber);
    RUN_TEST (test_repeated_disconnect);
    RUN_TEST (test_publisher_shutdown);
    return UNITY_END ();
}
