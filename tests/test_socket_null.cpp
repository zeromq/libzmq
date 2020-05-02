/*
    Copyright (c) 2007-2017 Contributors as noted in the AUTHORS file

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
