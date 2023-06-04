/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

SETUP_TEARDOWN_TESTCONTEXT

const int MAX_SENDS = 10000;

void test_change_before_connected ()
{
    int rc;

    void *bind_socket = test_context_socket (ZMQ_PUSH);
    void *connect_socket = test_context_socket (ZMQ_PULL);

    int val = 2;
    rc = zmq_setsockopt (connect_socket, ZMQ_RCVHWM, &val, sizeof (val));
    TEST_ASSERT_EQUAL_INT (0, rc);
    rc = zmq_setsockopt (bind_socket, ZMQ_SNDHWM, &val, sizeof (val));
    TEST_ASSERT_EQUAL_INT (0, rc);

    zmq_connect (connect_socket, "inproc://a");
    zmq_bind (bind_socket, "inproc://a");

    size_t placeholder = sizeof (val);
    val = 0;
    rc = zmq_getsockopt (bind_socket, ZMQ_SNDHWM, &val, &placeholder);
    TEST_ASSERT_EQUAL_INT (0, rc);
    TEST_ASSERT_EQUAL_INT (2, val);

    int send_count = 0;
    while (send_count < MAX_SENDS
           && zmq_send (bind_socket, NULL, 0, ZMQ_DONTWAIT) == 0)
        ++send_count;

    TEST_ASSERT_EQUAL_INT (4, send_count);

    test_context_socket_close (bind_socket);
    test_context_socket_close (connect_socket);
}

void test_change_after_connected ()
{
    int rc;

    void *bind_socket = test_context_socket (ZMQ_PUSH);
    void *connect_socket = test_context_socket (ZMQ_PULL);

    int val = 1;
    rc = zmq_setsockopt (connect_socket, ZMQ_RCVHWM, &val, sizeof (val));
    TEST_ASSERT_EQUAL_INT (0, rc);
    rc = zmq_setsockopt (bind_socket, ZMQ_SNDHWM, &val, sizeof (val));
    TEST_ASSERT_EQUAL_INT (0, rc);

    zmq_connect (connect_socket, "inproc://a");
    zmq_bind (bind_socket, "inproc://a");

    val = 5;
    rc = zmq_setsockopt (bind_socket, ZMQ_SNDHWM, &val, sizeof (val));
    TEST_ASSERT_EQUAL_INT (0, rc);

    size_t placeholder = sizeof (val);
    val = 0;
    rc = zmq_getsockopt (bind_socket, ZMQ_SNDHWM, &val, &placeholder);
    TEST_ASSERT_EQUAL_INT (0, rc);
    TEST_ASSERT_EQUAL_INT (5, val);

    int send_count = 0;
    while (send_count < MAX_SENDS
           && zmq_send (bind_socket, NULL, 0, ZMQ_DONTWAIT) == 0)
        ++send_count;

    TEST_ASSERT_EQUAL_INT (6, send_count);

    test_context_socket_close (bind_socket);
    test_context_socket_close (connect_socket);
}

int send_until_wouldblock (void *socket_)
{
    int send_count = 0;
    while (send_count < MAX_SENDS
           && zmq_send (socket_, &send_count, sizeof (send_count), ZMQ_DONTWAIT)
                == sizeof (send_count)) {
        ++send_count;
    }
    return send_count;
}

int test_fill_up_to_hwm (void *socket_, int sndhwm_)
{
    int send_count = send_until_wouldblock (socket_);
    fprintf (stderr, "sndhwm==%i, send_count==%i\n", sndhwm_, send_count);
    TEST_ASSERT_LESS_OR_EQUAL_INT (sndhwm_ + 1, send_count);
    TEST_ASSERT_GREATER_THAN_INT (sndhwm_ / 10, send_count);
    return send_count;
}

void test_decrease_when_full ()
{
    int rc;

    void *bind_socket = test_context_socket (ZMQ_PUSH);
    void *connect_socket = test_context_socket (ZMQ_PULL);

    int val = 1;
    rc = zmq_setsockopt (connect_socket, ZMQ_RCVHWM, &val, sizeof (val));
    TEST_ASSERT_EQUAL_INT (0, rc);

    int sndhwm = 100;
    rc = zmq_setsockopt (bind_socket, ZMQ_SNDHWM, &sndhwm, sizeof (sndhwm));
    TEST_ASSERT_EQUAL_INT (0, rc);

    zmq_bind (bind_socket, "inproc://a");
    zmq_connect (connect_socket, "inproc://a");

    //  we must wait for the connect to succeed here, unfortunately we don't
    //  have monitoring events for inproc, so we just hope SETTLE_TIME suffices
    msleep (SETTLE_TIME);

    // Fill up to hwm
    int send_count = test_fill_up_to_hwm (bind_socket, sndhwm);

    // Decrease snd hwm
    sndhwm = 70;
    rc = zmq_setsockopt (bind_socket, ZMQ_SNDHWM, &sndhwm, sizeof (sndhwm));
    TEST_ASSERT_EQUAL_INT (0, rc);

    int sndhwm_read = 0;
    size_t sndhwm_read_size = sizeof (sndhwm_read);
    rc =
      zmq_getsockopt (bind_socket, ZMQ_SNDHWM, &sndhwm_read, &sndhwm_read_size);
    TEST_ASSERT_EQUAL_INT (0, rc);
    TEST_ASSERT_EQUAL_INT (sndhwm, sndhwm_read);

    msleep (SETTLE_TIME);

    // Read out all data (should get up to previous hwm worth so none were dropped)
    int read_count = 0;
    int read_data = 0;
    while (
      read_count < MAX_SENDS
      && zmq_recv (connect_socket, &read_data, sizeof (read_data), ZMQ_DONTWAIT)
           == sizeof (read_data)) {
        TEST_ASSERT_EQUAL_INT (read_data, read_count);
        ++read_count;
    }

    TEST_ASSERT_EQUAL_INT (send_count, read_count);

    // Give io thread some time to catch up
    msleep (SETTLE_TIME);

    // Fill up to new hwm
    test_fill_up_to_hwm (bind_socket, sndhwm);

    test_context_socket_close (bind_socket);
    test_context_socket_close (connect_socket);
}


int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_change_before_connected);
    RUN_TEST (test_change_after_connected);
    RUN_TEST (test_decrease_when_full);

    return UNITY_END ();
}
