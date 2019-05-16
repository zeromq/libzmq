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

SETUP_TEARDOWN_TESTCONTEXT

//  Issue 566 describes a problem in libzmq v4.0.0 where a dealer to router
//  connection would fail randomly. The test works when the two sockets are
//  on the same context, and failed when they were on separate contexts.
//  Fixed by https://github.com/zeromq/libzmq/commit/be25cf.
void test_issue_566 ()
{
    char my_endpoint[MAX_SOCKET_STRING];
    void *ctx1 = zmq_ctx_new ();
    TEST_ASSERT_NOT_NULL (ctx1);

    void *ctx2 = zmq_ctx_new ();
    TEST_ASSERT_NOT_NULL (ctx2);

    void *router = zmq_socket (ctx1, ZMQ_ROUTER);
    int on = 1;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (router, ZMQ_ROUTER_MANDATORY, &on, sizeof (on)));
    bind_loopback_ipv4 (router, my_endpoint, sizeof (my_endpoint));

    //  Repeat often enough to be sure this works as it should
    for (int cycle = 0; cycle < 100; cycle++) {
        //  Create dealer with unique explicit routing id
        //  We assume the router learns this out-of-band
        void *dealer = zmq_socket (ctx2, ZMQ_DEALER);
        //  Leave space for NULL char from sprintf, gcc warning
        char routing_id[11];
        sprintf (routing_id, "%09d", cycle);
        TEST_ASSERT_SUCCESS_ERRNO (
          zmq_setsockopt (dealer, ZMQ_ROUTING_ID, routing_id, 10));
        int rcvtimeo = 1000;
        TEST_ASSERT_SUCCESS_ERRNO (
          zmq_setsockopt (dealer, ZMQ_RCVTIMEO, &rcvtimeo, sizeof (int)));
        TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (dealer, my_endpoint));

        //  Router will try to send to dealer, at short intervals.
        //  It typically takes 2-5 msec for the connection to establish
        //  on a loopback interface, but we'll allow up to one second
        //  before failing the test (e.g. for running on a debugger or
        //  a very slow system).
        for (int attempt = 0; attempt < 500; attempt++) {
            zmq_poll (NULL, 0, 2);
            int rc = zmq_send (router, routing_id, 10, ZMQ_SNDMORE);
            if (rc == -1 && errno == EHOSTUNREACH)
                continue;
            TEST_ASSERT_EQUAL (10, rc);
            send_string_expect_success (router, "HELLO", 0);
            break;
        }
        recv_string_expect_success (dealer, "HELLO", 0);
        close_zero_linger (dealer);
    }
    zmq_close (router);
    zmq_ctx_destroy (ctx1);
    zmq_ctx_destroy (ctx2);
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_issue_566);
    return UNITY_END ();
}
