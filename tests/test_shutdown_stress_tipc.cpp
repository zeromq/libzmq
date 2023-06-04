/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

#include <pthread.h>

void setUp ()
{
}

void tearDown ()
{
}

#define THREAD_COUNT 100

extern "C" {
static void *worker (void *ctx)
{
    void *s = zmq_socket (ctx, ZMQ_SUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (s, "tipc://{5560,0}@0.0.0"));

    //  Start closing the socket while the connecting process is underway.
    TEST_ASSERT_SUCCESS_ERRNO (zmq_close (s));

    return NULL;
}
}

void test_shutdown_stress_tipc ()
{
    void *s1;
    int i;
    int j;
    pthread_t threads[THREAD_COUNT];

    for (j = 0; j != 10; j++) {
        //  Check the shutdown with many parallel I/O threads.
        setup_test_context ();
        zmq_ctx_set (get_test_context (), ZMQ_IO_THREADS, 7);

        s1 = test_context_socket (ZMQ_PUB);

        TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (s1, "tipc://{5560,0,0}"));

        for (i = 0; i != THREAD_COUNT; i++) {
            TEST_ASSERT_SUCCESS_RAW_ERRNO (
              pthread_create (&threads[i], NULL, worker, get_test_context ()));
        }

        for (i = 0; i != THREAD_COUNT; i++) {
            TEST_ASSERT_SUCCESS_RAW_ERRNO (pthread_join (threads[i], NULL));
        }

        test_context_socket_close (s1);

        teardown_test_context ();
    }
}

int main ()
{
    if (!is_tipc_available ()) {
        printf ("TIPC environment unavailable, skipping test\n");
        return 77;
    }

    UNITY_BEGIN ();
    RUN_TEST (test_shutdown_stress_tipc);
    return UNITY_END ();
}
