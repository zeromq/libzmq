/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"

#include <unity.h>

void setUp ()
{
}

void tearDown ()
{
}

//  tests all socket-related functions with a NULL socket argument
void test_zmq_socket_null_context ()
{
    TEST_ASSERT_NULL (zmq_socket (NULL, ZMQ_PAIR));
    TEST_ASSERT_EQUAL_INT (EFAULT, errno); // TODO use EINVAL instead?
}

void test_zmq_close_null_socket ()
{
    int rc = zmq_close (NULL);
    TEST_ASSERT_EQUAL_INT (-1, rc);
    TEST_ASSERT_EQUAL_INT (ENOTSOCK, errno); // TODO use EINVAL instead?
}

void test_zmq_setsockopt_null_socket ()
{
    int hwm = 100;
    size_t hwm_size = sizeof hwm;
    int rc = zmq_setsockopt (NULL, ZMQ_SNDHWM, &hwm, hwm_size);
    TEST_ASSERT_EQUAL_INT (-1, rc);
    TEST_ASSERT_EQUAL_INT (ENOTSOCK, errno); // TODO use EINVAL instead?
}

void test_zmq_getsockopt_null_socket ()
{
    int hwm;
    size_t hwm_size = sizeof hwm;
    int rc = zmq_getsockopt (NULL, ZMQ_SNDHWM, &hwm, &hwm_size);
    TEST_ASSERT_EQUAL_INT (-1, rc);
    TEST_ASSERT_EQUAL_INT (ENOTSOCK, errno); // TODO use EINVAL instead?
}

void test_zmq_socket_monitor_null_socket ()
{
    int rc = zmq_socket_monitor (NULL, "inproc://monitor", ZMQ_EVENT_ALL);
    TEST_ASSERT_EQUAL_INT (-1, rc);
    TEST_ASSERT_EQUAL_INT (ENOTSOCK, errno); // TODO use EINVAL instead?
}

#ifdef ZMQ_BUILD_DRAFT_API
void test_zmq_join_null_socket ()
{
    int rc = zmq_join (NULL, "group");
    TEST_ASSERT_EQUAL_INT (-1, rc);
    TEST_ASSERT_EQUAL_INT (ENOTSOCK, errno); // TODO use EINVAL instead?
}

void test_zmq_leave_null_socket ()
{
    int rc = zmq_leave (NULL, "group");
    TEST_ASSERT_EQUAL_INT (-1, rc);
    TEST_ASSERT_EQUAL_INT (ENOTSOCK, errno); // TODO use EINVAL instead?
}
#endif


void test_zmq_bind_null_socket ()
{
    int rc = zmq_bind (NULL, "inproc://socket");
    TEST_ASSERT_EQUAL_INT (-1, rc);
    TEST_ASSERT_EQUAL_INT (ENOTSOCK, errno); // TODO use EINVAL instead?
}

void test_zmq_connect_null_socket ()
{
    int rc = zmq_connect (NULL, "inproc://socket");
    TEST_ASSERT_EQUAL_INT (-1, rc);
    TEST_ASSERT_EQUAL_INT (ENOTSOCK, errno); // TODO use EINVAL instead?
}

void test_zmq_unbind_null_socket ()
{
    int rc = zmq_unbind (NULL, "inproc://socket");
    TEST_ASSERT_EQUAL_INT (-1, rc);
    TEST_ASSERT_EQUAL_INT (ENOTSOCK, errno); // TODO use EINVAL instead?
}

void test_zmq_disconnect_null_socket ()
{
    int rc = zmq_disconnect (NULL, "inproc://socket");
    TEST_ASSERT_EQUAL_INT (-1, rc);
    TEST_ASSERT_EQUAL_INT (ENOTSOCK, errno); // TODO use EINVAL instead?
}

int main (void)
{
    UNITY_BEGIN ();
    RUN_TEST (test_zmq_socket_null_context);
    RUN_TEST (test_zmq_close_null_socket);
    RUN_TEST (test_zmq_setsockopt_null_socket);
    RUN_TEST (test_zmq_getsockopt_null_socket);
    RUN_TEST (test_zmq_socket_monitor_null_socket);
    RUN_TEST (test_zmq_bind_null_socket);
    RUN_TEST (test_zmq_connect_null_socket);
    RUN_TEST (test_zmq_unbind_null_socket);
    RUN_TEST (test_zmq_disconnect_null_socket);

#ifdef ZMQ_BUILD_DRAFT_API
    RUN_TEST (test_zmq_join_null_socket);
    RUN_TEST (test_zmq_leave_null_socket);
#endif

    return UNITY_END ();
}
