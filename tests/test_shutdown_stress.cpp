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

void setUp ()
{
}

void tearDown ()
{
}

#define THREAD_COUNT 100

struct thread_data
{
    char endpoint[MAX_SOCKET_STRING];
};

extern "C" {
static void worker (void *data_)
{
    struct thread_data *tdata = (struct thread_data *) data_;

    void *socket = zmq_socket (get_test_context (), ZMQ_SUB);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (socket, tdata->endpoint));

    //  Start closing the socket while the connecting process is underway.
    TEST_ASSERT_SUCCESS_ERRNO (zmq_close (socket));
}
}

void test_shutdown_stress ()
{
    void *threads[THREAD_COUNT];

    for (int j = 0; j != 10; j++) {
        //  Check the shutdown with many parallel I/O threads.
        struct thread_data tdata;
        setup_test_context ();
        zmq_ctx_set (get_test_context (), ZMQ_IO_THREADS, 7);

        void *socket = test_context_socket (ZMQ_PUB);

        bind_loopback_ipv4 (socket, tdata.endpoint, sizeof (tdata.endpoint));

        for (int i = 0; i != THREAD_COUNT; i++) {
            threads[i] = zmq_threadstart (&worker, &tdata);
        }

        for (int i = 0; i != THREAD_COUNT; i++) {
            zmq_threadclose (threads[i]);
        }

        test_context_socket_close (socket);

        teardown_test_context ();
    }
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_shutdown_stress);
    return UNITY_END ();
}
