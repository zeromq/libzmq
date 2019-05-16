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

void test ()
{
    //  Create a publisher
    void *pub = test_context_socket (ZMQ_XPUB);

    int hwm = 2000;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (pub, ZMQ_SNDHWM, &hwm, 4));

    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (pub, "inproc://soname"));

    //  set pub socket options
    int wait = 1;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (pub, ZMQ_XPUB_NODROP, &wait, 4));

    //  Create a subscriber
    void *sub = test_context_socket (ZMQ_SUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sub, "inproc://soname"));

    //  Subscribe for all messages.
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (sub, ZMQ_SUBSCRIBE, "", 0));

    //  we must wait for the subscription to be processed here, otherwise some
    //  or all published messages might be lost
    recv_string_expect_success (pub, "\1", 0);

    int hwmlimit = hwm - 1;
    int send_count = 0;

    //  Send an empty message
    for (int i = 0; i < hwmlimit; i++) {
        TEST_ASSERT_SUCCESS_ERRNO (zmq_send (pub, NULL, 0, 0));
        send_count++;
    }

    int recv_count = 0;
    do {
        //  Receive the message in the subscriber
        int rc = zmq_recv (sub, NULL, 0, 0);
        if (rc == -1) {
            TEST_ASSERT_EQUAL_INT (EAGAIN, errno);
            break;
        } else {
            TEST_ASSERT_EQUAL_INT (0, rc);
            recv_count++;

            if (recv_count == 1) {
                const int sub_rcvtimeo = 250;
                TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
                  sub, ZMQ_RCVTIMEO, &sub_rcvtimeo, sizeof (sub_rcvtimeo)));
            }
        }
    } while (true);

    TEST_ASSERT_EQUAL_INT (send_count, recv_count);

    //  Now test real blocking behavior
    //  Set a timeout, default is infinite
    int timeout = 0;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (pub, ZMQ_SNDTIMEO, &timeout, 4));

    send_count = 0;
    recv_count = 0;
    hwmlimit = hwm;

    //  Send an empty message until we get an error, which must be EAGAIN
    while (zmq_send (pub, "", 0, 0) == 0)
        send_count++;
    TEST_ASSERT_EQUAL_INT (EAGAIN, errno);

    while (zmq_recv (sub, NULL, 0, ZMQ_DONTWAIT) == 0)
        recv_count++;
    TEST_ASSERT_EQUAL_INT (send_count, recv_count);

    //  Clean up.
    test_context_socket_close (pub);
    test_context_socket_close (sub);
}

int main ()
{
    setup_test_environment ();
    UNITY_BEGIN ();
    RUN_TEST (test);
    return UNITY_END ();
}
