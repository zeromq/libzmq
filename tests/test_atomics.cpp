/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

#include <unity.h>

void setUp ()
{
}

void tearDown ()
{
}

void test ()
{
    void *counter = zmq_atomic_counter_new ();
    TEST_ASSERT_EQUAL_INT (0, zmq_atomic_counter_value (counter));
    TEST_ASSERT_EQUAL_INT (0, zmq_atomic_counter_inc (counter));
    TEST_ASSERT_EQUAL_INT (1, zmq_atomic_counter_inc (counter));
    TEST_ASSERT_EQUAL_INT (2, zmq_atomic_counter_inc (counter));
    TEST_ASSERT_EQUAL_INT (3, zmq_atomic_counter_value (counter));
    TEST_ASSERT_EQUAL_INT (1, zmq_atomic_counter_dec (counter));
    TEST_ASSERT_EQUAL_INT (1, zmq_atomic_counter_dec (counter));
    TEST_ASSERT_EQUAL_INT (0, zmq_atomic_counter_dec (counter));
    zmq_atomic_counter_set (counter, 2);
    TEST_ASSERT_EQUAL_INT (1, zmq_atomic_counter_dec (counter));
    TEST_ASSERT_EQUAL_INT (0, zmq_atomic_counter_dec (counter));
    zmq_atomic_counter_destroy (&counter);
}

int main ()
{
    UNITY_BEGIN ();
    RUN_TEST (test);
    return UNITY_END ();
}
