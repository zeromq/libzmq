/* SPDX-License-Identifier: MPL-2.0 */

/*
 * File for adding tests for ancillary API methods and other miscellaenous
 * API internals. Please ensure that when adding such tests into this file,
 * that they are short-lived so they do not trigger timeouts in the
 * CI build environments.
 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

void setUp ()
{
}

void tearDown ()
{
}

void test_version ()
{
    int major, minor, patch;

    zmq_version (&major, &minor, &patch);
    TEST_ASSERT_EQUAL_INT (ZMQ_VERSION_MAJOR, major);
    TEST_ASSERT_EQUAL_INT (ZMQ_VERSION_MINOR, minor);
    TEST_ASSERT_EQUAL_INT (ZMQ_VERSION_PATCH, patch);
}

void test_strerrror ()
{
    TEST_ASSERT_NOT_NULL (zmq_strerror (EINVAL));
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_version);
    RUN_TEST (test_strerrror);
    return UNITY_END ();
}
