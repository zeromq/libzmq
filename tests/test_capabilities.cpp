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
    //
    // Built-in transports
    //

    TEST_ASSERT_TRUE (zmq_has ("inproc"));
    TEST_ASSERT_TRUE (zmq_has ("tcp"));
    TEST_ASSERT_TRUE (zmq_has ("udp"));

    //
    // Optional transports (config/build time)
    //

#if defined(ZMQ_HAVE_IPC)
    TEST_ASSERT_TRUE (zmq_has ("ipc"));
#else
    TEST_ASSERT_FALSE (zmq_has ("ipc"));
#endif

#if defined(ZMQ_HAVE_OPENPGM)
    TEST_ASSERT_TRUE (zmq_has ("pgm"));
    TEST_ASSERT_TRUE (zmq_has ("epgm"));
#else
    TEST_ASSERT_FALSE (zmq_has ("pgm"));
    TEST_ASSERT_FALSE (zmq_has ("epgm"));
#endif

#if defined(ZMQ_HAVE_TIPC)
    TEST_ASSERT_TRUE (zmq_has ("tipc"));
#else
    TEST_ASSERT_FALSE (zmq_has ("tipc"));
#endif

#if defined(ZMQ_HAVE_NORM)
    TEST_ASSERT_TRUE (zmq_has ("norm"));
#else
    TEST_ASSERT_FALSE (zmq_has ("norm"));
#endif

#if defined(ZMQ_HAVE_VMCI)
    TEST_ASSERT_TRUE (zmq_has ("vmci"));
#else
    TEST_ASSERT_FALSE (zmq_has ("vmci"));
#endif

#if defined(ZMQ_HAVE_VSOCK)
    TEST_ASSERT_TRUE (zmq_has ("vsock"));
#else
    TEST_ASSERT_FALSE (zmq_has ("vsock"));
#endif

#if defined(ZMQ_HAVE_HVSOCKET)
    TEST_ASSERT_TRUE (zmq_has ("hv"));
#else
    TEST_ASSERT_FALSE (zmq_has ("hv"));
#endif

#if defined(ZMQ_HAVE_WS)
    TEST_ASSERT_TRUE (zmq_has ("ws"));
#else
    TEST_ASSERT_FALSE (zmq_has ("ws"));
#endif

#if defined(ZMQ_HAVE_WSS)
    TEST_ASSERT_TRUE (zmq_has ("wss"));
#else
    TEST_ASSERT_FALSE (zmq_has ("wss"));
#endif

    //
    // Security
    //

#if defined(ZMQ_HAVE_CURVE)
    TEST_ASSERT_TRUE (zmq_has ("curve"));
#else
    TEST_ASSERT_FALSE (zmq_has ("curve"));
#endif

#if defined(HAVE_LIBGSSAPI_KRB5)
    TEST_ASSERT_TRUE (zmq_has ("gssapi"));
#else
    TEST_ASSERT_FALSE (zmq_has ("gssapi"));
#endif

    //
    // Draft APIs
    //

#if defined(ZMQ_BUILD_DRAFT_API)
    TEST_ASSERT_TRUE (zmq_has ("draft"));
#else
    TEST_ASSERT_FALSE (zmq_has ("draft"));
#endif

    //
    // Absurd capability
    //

    TEST_ASSERT_FALSE (zmq_has ("Lorem ipsum dolor sit amet."));
}

int ZMQ_CDECL main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_capabilities);
    return UNITY_END ();
}
