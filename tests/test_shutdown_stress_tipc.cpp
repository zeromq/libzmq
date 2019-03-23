/*
    Copyright (c) 2007-2016 Contributors as noted in the AUTHORS file

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

#include <pthread.h>

void setUp ()
{
}

void tearDown ()
{
}

#define THREAD_COUNT 100

extern "C" {
static void *worker (void *s_)
{
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (s_, "tipc://{5560,0}@0.0.0"));

    //  Start closing the socket while the connecting process is underway.
    TEST_ASSERT_SUCCESS_ERRNO (zmq_close (s_));

    return NULL;
}
}

void test_shutdown_stress_tipc ()
{
    void *s1;
    void *s2;
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
            s2 = zmq_socket (get_test_context (), ZMQ_SUB);
            TEST_ASSERT_SUCCESS_RAW_ERRNO (
              pthread_create (&threads[i], NULL, worker, s2));
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
