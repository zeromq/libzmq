/*
    Copyright (c) 2007-2018 Contributors as noted in the AUTHORS file

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

#include <unity.h>

#ifndef ZMQ_BUILD_DRAFT_API
#error This test HAS to run only with ZMQ_BUILD_DRAFT_API
#endif //ZMQ_BUILD_DRAFT_API

void setUp ()
{
    setup_test_context ();
}

void tearDown ()
{
    teardown_test_context ();
}


void test_mute_peer ()
{
    int rc;
    size_t len = MAX_SOCKET_STRING;
    char buffer[255];
    char my_endpoint[MAX_SOCKET_STRING];
    void *router = test_context_socket (ZMQ_ROUTER);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (router, "inproc://test_mute"));
    TEST_ASSERT_SUCCESS_ERRNO (
    zmq_getsockopt (router, ZMQ_LAST_ENDPOINT, my_endpoint, &len));


    void *dealer1 = test_context_socket (ZMQ_DEALER);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (dealer1, ZMQ_ROUTING_ID, "X",
									1));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (dealer1, my_endpoint));


    void *dealer2 = test_context_socket (ZMQ_DEALER);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (dealer2, ZMQ_ROUTING_ID, "Y",
									1));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (dealer2, my_endpoint));

    //  Send 2 messages on each dealer* -> router
    send_string_expect_success (dealer1, "HelloX", 0);
    send_string_expect_success (dealer1, "HelloX", 0);

    send_string_expect_success (dealer2, "HelloY", 0);
    send_string_expect_success (dealer2, "HelloY", 0);

    //  Reading 1+1 should give two different identities
    int i = 0;
    for (i = 0; i < 2; ++i) {
	rc = zmq_recv (router, buffer, 255, 0);
	assert (rc == 1);

    bool d1 = strncmp(buffer, "X", strlen("X")) == 0;
    rc = zmq_recv (router, buffer, 255, 0);
    assert (rc == 6);
	if(d1)
	    assert (strncmp(buffer, "HelloX", strlen("HelloX")) == 0);
	else
	    assert (strncmp(buffer, "HelloY", strlen("HelloY")) == 0);
    }

    // Mute and unseen routing-id
    rc = zmq_mute_peer (router, "Z", 1, 0x1);
    assert (rc == -1);
    assert (errno == EHOSTUNREACH);

    //  Mute X
    rc = zmq_mute_peer (router, "X", 1, 0x1);
    assert (rc == 0);

    //  Now we should only receive from Y
    rc = zmq_recv (router, buffer, 255, 0);
    assert (rc == 1);

    assert (strncmp(buffer, "Y", 1) == 0);
    rc = zmq_recv (router, buffer, 255, 0);
    assert (strncmp(buffer, "HelloY", strlen("HelloY")) == 0);

    //  This should block / return EAGAIN
    rc = zmq_recv (router, buffer, 255, ZMQ_DONTWAIT);
    assert (rc == -1);
    assert (errno == EAGAIN);

    //  Poller should NOT have IN events
    zmq_pollitem_t poll_items[1] = {{router, 0, ZMQ_POLLIN, 0}};
    rc = zmq_poll (poll_items, 1, 10);
    assert (rc == 0);

    //  Unmute X
    rc = zmq_mute_peer (router, "X", 1, 0x0);
    assert (rc == 0);

    //  Poller should have IN events
    rc = zmq_poll (poll_items, 1, 10);
    assert (rc == 1);

    //  Now we should only receive from X
    rc = zmq_recv (router, buffer, 255, 0);
    assert (rc == 1);

    assert (strncmp(buffer, "X", 1) == 0);
    rc = zmq_recv (router, buffer, 255, 0);
    assert (strncmp(buffer, "HelloX", strlen("HelloX")) == 0);

    //  Nothing left on the buffer
    rc = zmq_recv (router, buffer, 255, ZMQ_DONTWAIT);
    assert (rc == -1);
    assert (errno == EAGAIN);

    //  Poller should NOT have IN events
    rc = zmq_poll (poll_items, 1, 10);
    assert (rc == 0);
}


int main (void)
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_mute_peer);

    return UNITY_END ();
}
