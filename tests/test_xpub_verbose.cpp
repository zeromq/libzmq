/*
    Copyright (c) 2018 Contributors as noted in the AUTHORS file

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

#include <unity.h>

void setUp ()
{
}
void tearDown ()
{
}

void test_xpub_verbose_one_sub ()
{
    int rc;
    char buffer[2];
    void *ctx = zmq_ctx_new ();
    TEST_ASSERT_NOT_NULL (ctx);

    void *pub = zmq_socket (ctx, ZMQ_XPUB);
    TEST_ASSERT_NOT_NULL (pub);
    rc = zmq_bind (pub, "inproc://soname");
    TEST_ASSERT_EQUAL_INT (0, rc);

    void *sub = zmq_socket (ctx, ZMQ_SUB);
    TEST_ASSERT_NOT_NULL (sub);
    rc = zmq_connect (sub, "inproc://soname");
    TEST_ASSERT_EQUAL_INT (0, rc);

    //  Subscribe for A
    rc = zmq_setsockopt (sub, ZMQ_SUBSCRIBE, "A", 1);
    TEST_ASSERT_EQUAL_INT (0, rc);

    // Receive subscriptions from subscriber
    rc = zmq_recv (pub, buffer, 2, 0);
    TEST_ASSERT_EQUAL_INT (2, rc);
    assert (buffer[0] == 1);
    assert (buffer[1] == 'A');

    // Subscribe socket for B instead
    rc = zmq_setsockopt (sub, ZMQ_SUBSCRIBE, "B", 1);
    TEST_ASSERT_EQUAL_INT (0, rc);

    // Receive subscriptions from subscriber
    rc = zmq_recv (pub, buffer, 2, 0);
    TEST_ASSERT_EQUAL_INT (2, rc);
    assert (buffer[0] == 1);
    assert (buffer[1] == 'B');

    //  Subscribe again for A again
    rc = zmq_setsockopt (sub, ZMQ_SUBSCRIBE, "A", 1);
    TEST_ASSERT_EQUAL_INT (0, rc);

    //  This time it is duplicated, so it will be filtered out
    rc = zmq_recv (pub, buffer, 1, ZMQ_DONTWAIT);
    TEST_ASSERT_EQUAL_INT (-1, rc);
    TEST_ASSERT_EQUAL_INT (EAGAIN, errno);

    int verbose = 1;
    rc = zmq_setsockopt (pub, ZMQ_XPUB_VERBOSE, &verbose, sizeof (int));
    TEST_ASSERT_EQUAL_INT (0, rc);

    // Subscribe socket for A again
    rc = zmq_setsockopt (sub, ZMQ_SUBSCRIBE, "A", 1);
    TEST_ASSERT_EQUAL_INT (0, rc);

    // This time with VERBOSE the duplicated sub will be received
    rc = zmq_recv (pub, buffer, 2, 0);
    TEST_ASSERT_EQUAL_INT (2, rc);
    assert (buffer[0] == 1);
    assert (buffer[1] == 'A');

    // Sending A message and B Message
    rc = zmq_send_const (pub, "A", 1, 0);
    TEST_ASSERT_EQUAL_INT (1, rc);

    rc = zmq_send_const (pub, "B", 1, 0);
    TEST_ASSERT_EQUAL_INT (1, rc);

    rc = zmq_recv (sub, buffer, 1, 0);
    TEST_ASSERT_EQUAL_INT (1, rc);
    assert (buffer[0] == 'A');

    rc = zmq_recv (sub, buffer, 1, 0);
    TEST_ASSERT_EQUAL_INT (1, rc);
    assert (buffer[0] == 'B');

    //  Clean up.
    rc = zmq_close (pub);
    TEST_ASSERT_EQUAL_INT (0, rc);
    rc = zmq_close (sub);
    TEST_ASSERT_EQUAL_INT (0, rc);
    rc = zmq_ctx_term (ctx);
    TEST_ASSERT_EQUAL_INT (0, rc);
}

void test_xpub_verbose_two_subs ()
{
    int rc;
    char buffer[2];
    void *ctx = zmq_ctx_new ();
    TEST_ASSERT_NOT_NULL (ctx);

    void *pub = zmq_socket (ctx, ZMQ_XPUB);
    TEST_ASSERT_NOT_NULL (pub);
    rc = zmq_bind (pub, "inproc://soname");
    TEST_ASSERT_EQUAL_INT (0, rc);

    void *sub0 = zmq_socket (ctx, ZMQ_SUB);
    TEST_ASSERT_NOT_NULL (sub0);
    rc = zmq_connect (sub0, "inproc://soname");
    TEST_ASSERT_EQUAL_INT (0, rc);

    void *sub1 = zmq_socket (ctx, ZMQ_SUB);
    TEST_ASSERT_NOT_NULL (sub1);
    rc = zmq_connect (sub1, "inproc://soname");
    TEST_ASSERT_EQUAL_INT (0, rc);

    //  Subscribe for A on the first socket
    rc = zmq_setsockopt (sub0, ZMQ_SUBSCRIBE, "A", 1);
    TEST_ASSERT_EQUAL_INT (0, rc);

    // Receive subscriptions from subscriber
    rc = zmq_recv (pub, buffer, 2, 0);
    TEST_ASSERT_EQUAL_INT (2, rc);
    assert (buffer[0] == 1);
    assert (buffer[1] == 'A');

    //  Subscribe for A on the second socket
    rc = zmq_setsockopt (sub1, ZMQ_SUBSCRIBE, "A", 1);
    TEST_ASSERT_EQUAL_INT (0, rc);

    //  This time it is duplicated, so it will be filtered out
    rc = zmq_recv (pub, buffer, 1, ZMQ_DONTWAIT);
    TEST_ASSERT_EQUAL_INT (-1, rc);
    TEST_ASSERT_EQUAL_INT (EAGAIN, errno);

    // Subscribe socket for B instead
    rc = zmq_setsockopt (sub0, ZMQ_SUBSCRIBE, "B", 1);
    TEST_ASSERT_EQUAL_INT (0, rc);

    // Receive subscriptions from subscriber
    rc = zmq_recv (pub, buffer, 2, 0);
    TEST_ASSERT_EQUAL_INT (2, rc);
    assert (buffer[0] == 1);
    assert (buffer[1] == 'B');

    int verbose = 1;
    rc = zmq_setsockopt (pub, ZMQ_XPUB_VERBOSE, &verbose, sizeof (int));
    TEST_ASSERT_EQUAL_INT (0, rc);

    // Subscribe socket for A again
    rc = zmq_setsockopt (sub1, ZMQ_SUBSCRIBE, "A", 1);
    TEST_ASSERT_EQUAL_INT (0, rc);

    // This time with VERBOSE the duplicated sub will be received
    rc = zmq_recv (pub, buffer, 2, 0);
    TEST_ASSERT_EQUAL_INT (2, rc);
    assert (buffer[0] == 1);
    assert (buffer[1] == 'A');

    // Sending A message and B Message
    rc = zmq_send_const (pub, "A", 1, 0);
    TEST_ASSERT_EQUAL_INT (1, rc);

    rc = zmq_send_const (pub, "B", 1, 0);
    TEST_ASSERT_EQUAL_INT (1, rc);

    rc = zmq_recv (sub0, buffer, 1, 0);
    TEST_ASSERT_EQUAL_INT (1, rc);
    assert (buffer[0] == 'A');

    rc = zmq_recv (sub1, buffer, 1, 0);
    TEST_ASSERT_EQUAL_INT (1, rc);
    assert (buffer[0] == 'A');

    rc = zmq_recv (sub0, buffer, 1, 0);
    TEST_ASSERT_EQUAL_INT (1, rc);
    assert (buffer[0] == 'B');

    //  Clean up.
    rc = zmq_close (pub);
    TEST_ASSERT_EQUAL_INT (0, rc);
    rc = zmq_close (sub0);
    TEST_ASSERT_EQUAL_INT (0, rc);
    rc = zmq_close (sub1);
    TEST_ASSERT_EQUAL_INT (0, rc);
    rc = zmq_ctx_term (ctx);
    TEST_ASSERT_EQUAL_INT (0, rc);
}

void test_xpub_verboser_one_sub ()
{
    int rc;
    char buffer[3];
    void *ctx = zmq_ctx_new ();
    TEST_ASSERT_NOT_NULL (ctx);

    //  Create a publisher
    void *pub = zmq_socket (ctx, ZMQ_XPUB);
    TEST_ASSERT_NOT_NULL (pub);
    rc = zmq_bind (pub, "inproc://soname");
    TEST_ASSERT_EQUAL_INT (0, rc);

    //  Create a subscriber
    void *sub = zmq_socket (ctx, ZMQ_SUB);
    TEST_ASSERT_NOT_NULL (sub);
    rc = zmq_connect (sub, "inproc://soname");
    TEST_ASSERT_EQUAL_INT (0, rc);

    //  Unsubscribe for A, does not exist yet
    rc = zmq_setsockopt (sub, ZMQ_UNSUBSCRIBE, "A", 1);
    TEST_ASSERT_EQUAL_INT (0, rc);

    //  Does not exist, so it will be filtered out by XSUB
    rc = zmq_recv (pub, buffer, 1, ZMQ_DONTWAIT);
    TEST_ASSERT_EQUAL_INT (-1, rc);
    TEST_ASSERT_EQUAL_INT (EAGAIN, errno);

    //  Subscribe for A
    rc = zmq_setsockopt (sub, ZMQ_SUBSCRIBE, "A", 1);
    TEST_ASSERT_EQUAL_INT (0, rc);

    // Receive subscriptions from subscriber
    rc = zmq_recv (pub, buffer, 2, 0);
    TEST_ASSERT_EQUAL_INT (2, rc);
    assert (buffer[0] == 1);
    assert (buffer[1] == 'A');

    //  Subscribe again for A again, XSUB will increase refcount
    rc = zmq_setsockopt (sub, ZMQ_SUBSCRIBE, "A", 1);
    TEST_ASSERT_EQUAL_INT (0, rc);

    //  This time it is duplicated, so it will be filtered out by XPUB
    rc = zmq_recv (pub, buffer, 1, ZMQ_DONTWAIT);
    TEST_ASSERT_EQUAL_INT (-1, rc);
    TEST_ASSERT_EQUAL_INT (EAGAIN, errno);

    //  Unsubscribe for A, this time it exists in XPUB
    rc = zmq_setsockopt (sub, ZMQ_UNSUBSCRIBE, "A", 1);
    TEST_ASSERT_EQUAL_INT (0, rc);

    //  XSUB refcounts and will not actually send unsub to PUB until the number
    //  of unsubs match the earlier subs
    rc = zmq_setsockopt (sub, ZMQ_UNSUBSCRIBE, "A", 1);
    TEST_ASSERT_EQUAL_INT (0, rc);

    // Receive unsubscriptions from subscriber
    rc = zmq_recv (pub, buffer, 2, 0);
    TEST_ASSERT_EQUAL_INT (2, rc);
    assert (buffer[0] == 0);
    assert (buffer[1] == 'A');

    //  XSUB only sends the last and final unsub, so XPUB will only receive 1
    rc = zmq_recv (pub, buffer, 1, ZMQ_DONTWAIT);
    TEST_ASSERT_EQUAL_INT (-1, rc);
    TEST_ASSERT_EQUAL_INT (EAGAIN, errno);

    //  Unsubscribe for A, does not exist anymore
    rc = zmq_setsockopt (sub, ZMQ_UNSUBSCRIBE, "A", 1);
    TEST_ASSERT_EQUAL_INT (0, rc);

    //  Does not exist, so it will be filtered out by XSUB
    rc = zmq_recv (pub, buffer, 1, ZMQ_DONTWAIT);
    TEST_ASSERT_EQUAL_INT (-1, rc);
    TEST_ASSERT_EQUAL_INT (EAGAIN, errno);

    int verbose = 1;
    rc = zmq_setsockopt (pub, ZMQ_XPUB_VERBOSER, &verbose, sizeof (int));
    TEST_ASSERT_EQUAL_INT (0, rc);

    // Subscribe socket for A again
    rc = zmq_setsockopt (sub, ZMQ_SUBSCRIBE, "A", 1);
    TEST_ASSERT_EQUAL_INT (0, rc);

    // Receive subscriptions from subscriber, did not exist anymore
    rc = zmq_recv (pub, buffer, 2, 0);
    TEST_ASSERT_EQUAL_INT (2, rc);
    assert (buffer[0] == 1);
    assert (buffer[1] == 'A');

    // Sending A message to make sure everything still works
    rc = zmq_send_const (pub, "A", 1, 0);
    TEST_ASSERT_EQUAL_INT (1, rc);

    rc = zmq_recv (sub, buffer, 1, 0);
    TEST_ASSERT_EQUAL_INT (1, rc);
    assert (buffer[0] == 'A');

    //  Unsubscribe for A, this time it exists
    rc = zmq_setsockopt (sub, ZMQ_UNSUBSCRIBE, "A", 1);
    TEST_ASSERT_EQUAL_INT (0, rc);

    // Receive unsubscriptions from subscriber
    rc = zmq_recv (pub, buffer, 2, 0);
    TEST_ASSERT_EQUAL_INT (2, rc);
    assert (buffer[0] == 0);
    assert (buffer[1] == 'A');

    //  Unsubscribe for A again, it does not exist anymore so XSUB will filter
    rc = zmq_setsockopt (sub, ZMQ_UNSUBSCRIBE, "A", 1);
    TEST_ASSERT_EQUAL_INT (0, rc);

    //  XSUB only sends unsub if it matched it in its trie, IOW: it will only
    //  send it if it existed in the first place even with XPUB_VERBBOSER
    rc = zmq_recv (pub, buffer, 1, ZMQ_DONTWAIT);
    TEST_ASSERT_EQUAL_INT (-1, rc);
    TEST_ASSERT_EQUAL_INT (EAGAIN, errno);

    //  Clean up.
    rc = zmq_close (pub);
    TEST_ASSERT_EQUAL_INT (0, rc);
    rc = zmq_close (sub);
    TEST_ASSERT_EQUAL_INT (0, rc);
    rc = zmq_ctx_term (ctx);
    TEST_ASSERT_EQUAL_INT (0, rc);
}

void test_xpub_verboser_two_subs ()
{
    int rc;
    char buffer[3];
    void *ctx = zmq_ctx_new ();
    TEST_ASSERT_NOT_NULL (ctx);

    void *pub = zmq_socket (ctx, ZMQ_XPUB);
    TEST_ASSERT_NOT_NULL (pub);
    rc = zmq_bind (pub, "inproc://soname");
    TEST_ASSERT_EQUAL_INT (0, rc);

    void *sub0 = zmq_socket (ctx, ZMQ_SUB);
    TEST_ASSERT_NOT_NULL (sub0);
    rc = zmq_connect (sub0, "inproc://soname");
    TEST_ASSERT_EQUAL_INT (0, rc);

    void *sub1 = zmq_socket (ctx, ZMQ_SUB);
    TEST_ASSERT_NOT_NULL (sub1);
    rc = zmq_connect (sub1, "inproc://soname");
    TEST_ASSERT_EQUAL_INT (0, rc);

    //  Subscribe for A
    rc = zmq_setsockopt (sub0, ZMQ_SUBSCRIBE, "A", 1);
    TEST_ASSERT_EQUAL_INT (0, rc);

    // Receive subscriptions from subscriber
    rc = zmq_recv (pub, buffer, 2, 0);
    TEST_ASSERT_EQUAL_INT (2, rc);
    assert (buffer[0] == 1);
    assert (buffer[1] == 'A');

    //  Subscribe again for A on the other socket
    rc = zmq_setsockopt (sub1, ZMQ_SUBSCRIBE, "A", 1);
    TEST_ASSERT_EQUAL_INT (0, rc);

    //  This time it is duplicated, so it will be filtered out by XPUB
    rc = zmq_recv (pub, buffer, 1, ZMQ_DONTWAIT);
    TEST_ASSERT_EQUAL_INT (-1, rc);
    TEST_ASSERT_EQUAL_INT (EAGAIN, errno);

    //  Unsubscribe for A, this time it exists in XPUB
    rc = zmq_setsockopt (sub0, ZMQ_UNSUBSCRIBE, "A", 1);
    TEST_ASSERT_EQUAL_INT (0, rc);

    //  sub1 is still subscribed, so no notification
    rc = zmq_recv (pub, buffer, 1, ZMQ_DONTWAIT);
    TEST_ASSERT_EQUAL_INT (-1, rc);
    TEST_ASSERT_EQUAL_INT (EAGAIN, errno);

    //  Unsubscribe the second socket to trigger the notification
    rc = zmq_setsockopt (sub1, ZMQ_UNSUBSCRIBE, "A", 1);
    TEST_ASSERT_EQUAL_INT (0, rc);

    // Receive unsubscriptions since all sockets are gone
    rc = zmq_recv (pub, buffer, 2, 0);
    TEST_ASSERT_EQUAL_INT (2, rc);
    assert (buffer[0] == 0);
    assert (buffer[1] == 'A');

    //  Make really sure there is only one notification
    rc = zmq_recv (pub, buffer, 1, ZMQ_DONTWAIT);
    TEST_ASSERT_EQUAL_INT (-1, rc);
    TEST_ASSERT_EQUAL_INT (EAGAIN, errno);

    int verbose = 1;
    rc = zmq_setsockopt (pub, ZMQ_XPUB_VERBOSER, &verbose, sizeof (int));
    TEST_ASSERT_EQUAL_INT (0, rc);

    // Subscribe socket for A again
    rc = zmq_setsockopt (sub0, ZMQ_SUBSCRIBE, "A", 1);
    TEST_ASSERT_EQUAL_INT (0, rc);

    // Subscribe socket for A again
    rc = zmq_setsockopt (sub1, ZMQ_SUBSCRIBE, "A", 1);
    TEST_ASSERT_EQUAL_INT (0, rc);

    // Receive subscriptions from subscriber, did not exist anymore
    rc = zmq_recv (pub, buffer, 2, 0);
    TEST_ASSERT_EQUAL_INT (2, rc);
    assert (buffer[0] == 1);
    assert (buffer[1] == 'A');

    //  VERBOSER is set, so subs from both sockets are received
    rc = zmq_recv (pub, buffer, 2, 0);
    TEST_ASSERT_EQUAL_INT (2, rc);
    assert (buffer[0] == 1);
    assert (buffer[1] == 'A');

    // Sending A message to make sure everything still works
    rc = zmq_send_const (pub, "A", 1, 0);
    TEST_ASSERT_EQUAL_INT (1, rc);

    rc = zmq_recv (sub0, buffer, 1, 0);
    TEST_ASSERT_EQUAL_INT (1, rc);
    assert (buffer[0] == 'A');

    rc = zmq_recv (sub1, buffer, 1, 0);
    TEST_ASSERT_EQUAL_INT (1, rc);
    assert (buffer[0] == 'A');

    //  Unsubscribe for A
    rc = zmq_setsockopt (sub1, ZMQ_UNSUBSCRIBE, "A", 1);
    TEST_ASSERT_EQUAL_INT (0, rc);

    // Receive unsubscriptions from first subscriber due to VERBOSER
    rc = zmq_recv (pub, buffer, 2, 0);
    TEST_ASSERT_EQUAL_INT (2, rc);
    assert (buffer[0] == 0);
    assert (buffer[1] == 'A');

    //  Unsubscribe for A again from the other socket
    rc = zmq_setsockopt (sub0, ZMQ_UNSUBSCRIBE, "A", 1);
    TEST_ASSERT_EQUAL_INT (0, rc);

    // Receive unsubscriptions from first subscriber due to VERBOSER
    rc = zmq_recv (pub, buffer, 2, 0);
    TEST_ASSERT_EQUAL_INT (2, rc);
    assert (buffer[0] == 0);
    assert (buffer[1] == 'A');

    //  Unsubscribe again to make sure it gets filtered now
    rc = zmq_setsockopt (sub1, ZMQ_UNSUBSCRIBE, "A", 1);
    TEST_ASSERT_EQUAL_INT (0, rc);

    //  Unmatched, so XSUB filters even with VERBOSER
    rc = zmq_recv (pub, buffer, 1, ZMQ_DONTWAIT);
    TEST_ASSERT_EQUAL_INT (-1, rc);
    TEST_ASSERT_EQUAL_INT (EAGAIN, errno);

    //  Clean up.
    rc = zmq_close (pub);
    TEST_ASSERT_EQUAL_INT (0, rc);
    rc = zmq_close (sub0);
    TEST_ASSERT_EQUAL_INT (0, rc);
    rc = zmq_close (sub1);
    TEST_ASSERT_EQUAL_INT (0, rc);
    rc = zmq_ctx_term (ctx);
    TEST_ASSERT_EQUAL_INT (0, rc);
}

int main (void)
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_xpub_verbose_one_sub);
    RUN_TEST (test_xpub_verbose_two_subs);
    RUN_TEST (test_xpub_verboser_one_sub);
    RUN_TEST (test_xpub_verboser_two_subs);

    return 0;
}
