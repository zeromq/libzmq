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

SETUP_TEARDOWN_TESTCONTEXT

void test_timeo ()
{
    void *frontend = test_context_socket (ZMQ_DEALER);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (frontend, "inproc://timeout_test"));

    //  Receive on disconnected socket returns immediately
    char buffer[32];
    TEST_ASSERT_FAILURE_ERRNO (EAGAIN,
                               zmq_recv (frontend, buffer, 32, ZMQ_DONTWAIT));


    //  Check whether receive timeout is honored
    const int timeout = 250;
    const int jitter = 50;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (frontend, ZMQ_RCVTIMEO, &timeout, sizeof (int)));

    void *stopwatch = zmq_stopwatch_start ();
    TEST_ASSERT_FAILURE_ERRNO (EAGAIN, zmq_recv (frontend, buffer, 32, 0));
    unsigned int elapsed = zmq_stopwatch_stop (stopwatch) / 1000;
    TEST_ASSERT_GREATER_THAN_INT (timeout - jitter, elapsed);
    if (elapsed >= timeout + jitter) {
        // we cannot assert this on a non-RT system
        fprintf (stderr,
                 "zmq_recv took quite long, with a timeout of %i ms, it took "
                 "actually %i ms\n",
                 timeout, elapsed);
    }

    //  Check that normal message flow works as expected
    void *backend = test_context_socket (ZMQ_DEALER);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (backend, "inproc://timeout_test"));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (backend, ZMQ_SNDTIMEO, &timeout, sizeof (int)));

    send_string_expect_success (backend, "Hello", 0);
    recv_string_expect_success (frontend, "Hello", 0);

    //  Clean-up
    test_context_socket_close (backend);
    test_context_socket_close (frontend);
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_timeo);
    return UNITY_END ();
}
