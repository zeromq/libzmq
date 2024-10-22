/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

#include <stdio.h>
#include <stdlib.h>
#include <vector>

SETUP_TEARDOWN_TESTCONTEXT

void test_system_max ()
{
    // Keep allocating sockets until we run out of system resources
    const int no_of_sockets = 2 * 65536;
    zmq_ctx_set (get_test_context (), ZMQ_MAX_SOCKETS, no_of_sockets);
    std::vector<void *> sockets;

    while (true) {
        void *socket = zmq_socket (get_test_context (), ZMQ_PAIR);
        if (!socket)
            break;
        sockets.push_back (socket);
    }
    TEST_ASSERT_LESS_OR_EQUAL (no_of_sockets,
                               static_cast<int> (sockets.size ()));
    printf ("Socket creation failed after %i sockets\n",
            static_cast<int> (sockets.size ()));

    //  System is out of resources, further calls to zmq_socket should return NULL
    for (unsigned int i = 0; i < 10; ++i) {
        TEST_ASSERT_NULL (zmq_socket (get_test_context (), ZMQ_PAIR));
    }
    // Clean up.
    for (unsigned int i = 0; i < sockets.size (); ++i)
        TEST_ASSERT_SUCCESS_ERRNO (zmq_close (sockets[i]));
}

void test_zmq_default_max ()
{
    //  Keep allocating sockets until we hit the default limit
    std::vector<void *> sockets;

    while (true) {
        void *socket = zmq_socket (get_test_context (), ZMQ_PAIR);
        if (!socket)
            break;
        sockets.push_back (socket);
    }
    //  We may stop sooner if system has fewer available sockets
    TEST_ASSERT_LESS_OR_EQUAL (ZMQ_MAX_SOCKETS_DFLT, sockets.size ());

    //  Further calls to zmq_socket should return NULL
    for (unsigned int i = 0; i < 10; ++i) {
        TEST_ASSERT_NULL (zmq_socket (get_test_context (), ZMQ_PAIR));
    }

    //  Clean up
    for (unsigned int i = 0; i < sockets.size (); ++i)
        TEST_ASSERT_SUCCESS_ERRNO (zmq_close (sockets[i]));
}

int main (void)
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_system_max);
    RUN_TEST (test_zmq_default_max);
    return UNITY_END ();
}
