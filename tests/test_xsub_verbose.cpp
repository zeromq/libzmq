/*
    Copyright (c) 2021 Contributors as noted in the AUTHORS file

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

const uint8_t unsubscribe_a_msg[] = {0, 'A'};
const uint8_t subscribe_a_msg[] = {1, 'A'};

const char test_endpoint[] = "inproc://soname";

void test_xsub_verbose_unsubscribe ()
{
    void *pub = test_context_socket (ZMQ_XPUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (pub, test_endpoint));

    void *sub = test_context_socket (ZMQ_XSUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sub, test_endpoint));

    // set option ZMQ_XPUB_VERBOSER to get all messages
    int xbup_verboser = 1;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (pub, ZMQ_XPUB_VERBOSER, &xbup_verboser, sizeof (int)));

    // unsubscribe from topic A, does not exist yet
    send_array_expect_success (sub, unsubscribe_a_msg, 0);

    // does not exist, so it will be filtered out by XSUB
    TEST_ASSERT_FAILURE_ERRNO (EAGAIN, zmq_recv (pub, NULL, 0, ZMQ_DONTWAIT));

    // subscribe to topic A
    send_array_expect_success (sub, subscribe_a_msg, 0);

    // receive subscription from subscriber
    recv_array_expect_success (pub, subscribe_a_msg, 0);

    // subscribe again to topic A
    send_array_expect_success (sub, subscribe_a_msg, 0);

    // receive subscription from subscriber
    recv_array_expect_success (pub, subscribe_a_msg, 0);

    // unsubscribe from topic A
    send_array_expect_success (sub, unsubscribe_a_msg, 0);

    // The first unsubscribe will be filtered out
    TEST_ASSERT_FAILURE_ERRNO (EAGAIN, zmq_recv (pub, NULL, 0, ZMQ_DONTWAIT));

    // unsubscribe again from topic A
    send_array_expect_success (sub, unsubscribe_a_msg, 0);

    // receive unsubscription from subscriber
    recv_array_expect_success (pub, unsubscribe_a_msg, 0);

    // set option ZMQ_XSUB_VERBOSE_UNSUBSCRIBE to get duplicate unsubscribes
    int xsub_verbose = 1;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      sub, ZMQ_XSUB_VERBOSE_UNSUBSCRIBE, &xsub_verbose, sizeof (int)));

    // unsubscribe from topic A, does not exist yet
    send_array_expect_success (sub, unsubscribe_a_msg, 0);

    // does not exist, but with ZMQ_XSUB_VERBOSE_UNSUBSCRIBE set it will be forwarded anyway
    recv_array_expect_success (pub, unsubscribe_a_msg, 0);

    // subscribe to topic A
    send_array_expect_success (sub, subscribe_a_msg, 0);

    // receive subscription from subscriber
    recv_array_expect_success (pub, subscribe_a_msg, 0);

    // subscribe again to topic A
    send_array_expect_success (sub, subscribe_a_msg, 0);

    // receive subscription from subscriber
    recv_array_expect_success (pub, subscribe_a_msg, 0);

    // unsubscribe from topic A
    send_array_expect_success (sub, unsubscribe_a_msg, 0);

    // receive unsubscription from subscriber
    recv_array_expect_success (pub, unsubscribe_a_msg, 0);

    // unsubscribe again from topic A
    send_array_expect_success (sub, unsubscribe_a_msg, 0);

    // receive unsubscription from subscriber
    recv_array_expect_success (pub, unsubscribe_a_msg, 0);

    //  Clean up.
    test_context_socket_close (pub);
    test_context_socket_close (sub);
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_xsub_verbose_unsubscribe);

    return UNITY_END ();
}
