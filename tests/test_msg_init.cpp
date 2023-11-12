/* SPDX-License-Identifier: MPL-2.0 */

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

int main (void)
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_msg_init);
    RUN_TEST (test_msg_init_size);
    RUN_TEST (test_msg_init_buffer);
    return UNITY_END ();
}
