/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

void setUp ()
{
}

void tearDown ()
{
}

void test_capabilities ()
{
#if defined(ZMQ_HAVE_IPC)
    TEST_ASSERT_TRUE (zmq_has ("ipc"));
#else
    TEST_ASSERT_TRUE (!zmq_has ("ipc"));
#endif

#if defined(ZMQ_HAVE_OPENPGM)
    TEST_ASSERT_TRUE (zmq_has ("pgm"));
#else
    TEST_ASSERT_TRUE (!zmq_has ("pgm"));
#endif

#if defined(ZMQ_HAVE_TIPC)
    TEST_ASSERT_TRUE (zmq_has ("tipc"));
#else
    TEST_ASSERT_TRUE (!zmq_has ("tipc"));
#endif

#if defined(ZMQ_HAVE_NORM)
    TEST_ASSERT_TRUE (zmq_has ("norm"));
#else
    TEST_ASSERT_TRUE (!zmq_has ("norm"));
#endif

#if defined(ZMQ_HAVE_CURVE)
    TEST_ASSERT_TRUE (zmq_has ("curve"));
#else
    TEST_ASSERT_TRUE (!zmq_has ("curve"));
#endif

#if defined(HAVE_LIBGSSAPI_KRB5)
    TEST_ASSERT_TRUE (zmq_has ("gssapi"));
#else
    TEST_ASSERT_TRUE (!zmq_has ("gssapi"));
#endif

#if defined(ZMQ_HAVE_VMCI)
    TEST_ASSERT_TRUE (zmq_has ("vmci"));
#else
    TEST_ASSERT_TRUE (!zmq_has ("vmci"));
#endif

#if defined(ZMQ_BUILD_DRAFT_API)
    TEST_ASSERT_TRUE (zmq_has ("draft"));
#else
    TEST_ASSERT_TRUE (!zmq_has ("draft"));
#endif
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_capabilities);
    return UNITY_END ();
}
