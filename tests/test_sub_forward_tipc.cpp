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
    //  First, create an intermediate device.
    void *xpub = test_context_socket (ZMQ_XPUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (xpub, "tipc://{5560,0,0}"));
    void *xsub = test_context_socket (ZMQ_XSUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (xsub, "tipc://{5561,0,0}"));

    //  Create a publisher.
    void *pub = test_context_socket (ZMQ_PUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (pub, "tipc://{5561,0}@0.0.0"));

    //  Create a subscriber.
    void *sub = test_context_socket (ZMQ_SUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sub, "tipc://{5560,0}@0.0.0"));

    // TODO the remainder of this method is duplicated with test_sub_forward

    //  Subscribe for all messages.
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (sub, ZMQ_SUBSCRIBE, "", 0));

    //  Pass the subscription upstream through the device
    char buff[32];
    int size;
    TEST_ASSERT_SUCCESS_ERRNO (size = zmq_recv (xpub, buff, sizeof (buff), 0));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_send (xsub, buff, size, 0));

    //  Wait a bit till the subscription gets to the publisher
    msleep (SETTLE_TIME);

    //  Send an empty message
    send_string_expect_success (pub, "", 0);

    //  Pass the message downstream through the device
    TEST_ASSERT_SUCCESS_ERRNO (size = zmq_recv (xsub, buff, sizeof (buff), 0));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_send (xpub, buff, size, 0));

    //  Receive the message in the subscriber
    recv_string_expect_success (sub, "", 0);

    //  Clean up.
    test_context_socket_close (xpub);
    test_context_socket_close (xsub);
    test_context_socket_close (pub);
    test_context_socket_close (sub);
}

int main ()
{
    if (!is_tipc_available ()) {
        printf ("TIPC environment unavailable, skipping test\n");
        return 77;
    }

    UNITY_BEGIN ();
    RUN_TEST (test);
    return UNITY_END ();
}
