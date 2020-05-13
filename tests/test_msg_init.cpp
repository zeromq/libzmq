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
#include "testutil_unity.hpp"

#include <string.h>

SETUP_TEARDOWN_TESTCONTEXT

void test_msg_init ()
{
    zmq_msg_t msg;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init (&msg));
    TEST_ASSERT_EQUAL_INT (0, zmq_msg_size (&msg));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg));
}

void test_msg_init_size ()
{
    const char *data = "foobar";
    zmq_msg_t msg;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init_size (&msg, 6));
    TEST_ASSERT_EQUAL_INT (6, zmq_msg_size (&msg));
    memcpy (zmq_msg_data (&msg), data, 6);
    TEST_ASSERT_EQUAL_STRING_LEN (data, zmq_msg_data (&msg), 6);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg));

    zmq_msg_t msg2;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init_size (&msg2, 0));
    TEST_ASSERT_EQUAL_INT (0, zmq_msg_size (&msg2));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg2));
}

void test_msg_init_buffer ()
{
    const char *data = "foobar";
    zmq_msg_t msg;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init_buffer (&msg, data, 6));
    TEST_ASSERT_EQUAL_INT (6, zmq_msg_size (&msg));
    TEST_ASSERT (data != zmq_msg_data (&msg));
    TEST_ASSERT_EQUAL_STRING_LEN (data, zmq_msg_data (&msg), 6);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg));

    zmq_msg_t msg2;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init_buffer (&msg2, NULL, 0));
    TEST_ASSERT_EQUAL_INT (0, zmq_msg_size (&msg2));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg2));
}

void test_msg_init_allocator ()
{
#if defined(ZMQ_BUILD_DRAFT_API)
    const char *data = "foobar";
    zmq_msg_t msg;
    void *allocator = zmq_msg_allocator_new (ZMQ_MSG_ALLOCATOR_GLOBAL_POOL);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init_allocator (&msg, 6, allocator));
    TEST_ASSERT_EQUAL_INT (6, zmq_msg_size (&msg));
    memcpy (zmq_msg_data (&msg), data, 6);
    TEST_ASSERT_EQUAL_STRING_LEN (data, zmq_msg_data (&msg), 6);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg));

    zmq_msg_t msg2;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init_allocator (&msg2, 0, allocator));
    TEST_ASSERT_EQUAL_INT (0, zmq_msg_size (&msg2));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg2));

    void *data3 = malloc (1024);
    memset (data3, 1, 1024);
    zmq_msg_t msg3;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init_allocator (&msg3, 1024, allocator));
    TEST_ASSERT_EQUAL_INT (1024, zmq_msg_size (&msg3));
    memcpy (zmq_msg_data (&msg3), data3, 1024);
    TEST_ASSERT_EQUAL_MEMORY (data3, zmq_msg_data (&msg3), 1024);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg3));

    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_allocator_destroy (&allocator));
#else
    TEST_IGNORE_MESSAGE ("libzmq without DRAFT support, ignoring test");
#endif
}

int main (void)
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_msg_init);
    RUN_TEST (test_msg_init_size);
    RUN_TEST (test_msg_init_buffer);
    RUN_TEST (test_msg_init_allocator);
    return UNITY_END ();
}
