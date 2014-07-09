/*
    Copyright (c) 2007-2014 Contributors as noted in the AUTHORS file

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "testutil.hpp"

static void pusher (void *ctx)
{
    // Connect first
    void *connectSocket = zmq_socket (ctx, ZMQ_PAIR);
    assert (connectSocket);
    int rc = zmq_connect (connectSocket, "inproc://sink");
    assert (rc == 0);

    // Queue up some data
    rc = zmq_send_const (connectSocket, "foobar", 6, 0);
    assert (rc == 6);

    // Cleanup
    rc = zmq_close (connectSocket);
    assert (rc == 0);
}

static void simult_conn (void *payload)
{
    // Pull out arguments - context followed by endpoint string
    void* ctx   = (void*)((void**)payload)[0];
    char* endpt = (char*)((void**)payload)[1];

    // Connect
    void *connectSocket = zmq_socket (ctx, ZMQ_SUB);
    assert (connectSocket);
    int rc = zmq_connect (connectSocket, endpt);
    assert (rc == 0);

    // Cleanup
    rc = zmq_close (connectSocket);
    assert (rc == 0);
}

static void simult_bind (void *payload)
{
    // Pull out arguments - context followed by endpoint string
    void* ctx   = (void*)((void**)payload)[0];
    char* endpt = (char*)((void**)payload)[1];

    // Bind
    void *bindSocket = zmq_socket (ctx, ZMQ_PUB);
    assert (bindSocket);
    int rc = zmq_bind (bindSocket, endpt);
    assert (rc == 0);

    // Cleanup
    rc = zmq_close (bindSocket);
    assert (rc == 0);
}

void test_bind_before_connect ()
{
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    // Bind first
    void *bindSocket = zmq_socket (ctx, ZMQ_PAIR);
    assert (bindSocket);
    int rc = zmq_bind (bindSocket, "inproc://bbc");
    assert (rc == 0);

    // Now connect
    void *connectSocket = zmq_socket (ctx, ZMQ_PAIR);
    assert (connectSocket);
    rc = zmq_connect (connectSocket, "inproc://bbc");
    assert (rc == 0);

    // Queue up some data
    rc = zmq_send_const (connectSocket, "foobar", 6, 0);
    assert (rc == 6);

    // Read pending message
    zmq_msg_t msg;
    rc = zmq_msg_init (&msg);
    assert (rc == 0);
    rc = zmq_msg_recv (&msg, bindSocket, 0);
    assert (rc == 6);
    void *data = zmq_msg_data (&msg);
    assert (memcmp ("foobar", data, 6) == 0);

    // Cleanup
    rc = zmq_close (connectSocket);
    assert (rc == 0);

    rc = zmq_close (bindSocket);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);
}

void test_connect_before_bind ()
{
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    // Connect first
    void *connectSocket = zmq_socket (ctx, ZMQ_PAIR);
    assert (connectSocket);
    int rc = zmq_connect (connectSocket, "inproc://cbb");
    assert (rc == 0);

    // Queue up some data
    rc = zmq_send_const (connectSocket, "foobar", 6, 0);
    assert (rc == 6);

    // Now bind
    void *bindSocket = zmq_socket (ctx, ZMQ_PAIR);
    assert (bindSocket);
    rc = zmq_bind (bindSocket, "inproc://cbb");
    assert (rc == 0);

    // Read pending message
    zmq_msg_t msg;
    rc = zmq_msg_init (&msg);
    assert (rc == 0);
    rc = zmq_msg_recv (&msg, bindSocket, 0);
    assert (rc == 6);
    void *data = zmq_msg_data (&msg);
    assert (memcmp ("foobar", data, 6) == 0);

    // Cleanup
    rc = zmq_close (connectSocket);
    assert (rc == 0);

    rc = zmq_close (bindSocket);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);
}

void test_connect_before_bind_pub_sub ()
{
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    // Connect first
    void *connectSocket = zmq_socket (ctx, ZMQ_PUB);
    assert (connectSocket);
    int rc = zmq_connect (connectSocket, "inproc://cbbps");
    assert (rc == 0);

    // Queue up some data, this will be dropped
    rc = zmq_send_const (connectSocket, "before", 6, 0);
    assert (rc == 6);

    // Now bind
    void *bindSocket = zmq_socket (ctx, ZMQ_SUB);
    assert (bindSocket);
    rc = zmq_setsockopt (bindSocket, ZMQ_SUBSCRIBE, "", 0);
    assert (rc == 0);
    rc = zmq_bind (bindSocket, "inproc://cbbps");
    assert (rc == 0);

    // Wait for pub-sub connection to happen
    msleep (SETTLE_TIME);

    // Queue up some data, this not will be dropped
    rc = zmq_send_const (connectSocket, "after", 6, 0);
    assert (rc == 6);

    // Read pending message
    zmq_msg_t msg;
    rc = zmq_msg_init (&msg);
    assert (rc == 0);
    rc = zmq_msg_recv (&msg, bindSocket, 0);
    assert (rc == 6);
    void *data = zmq_msg_data (&msg);
    assert (memcmp ("after", data, 5) == 0);

    // Cleanup
    rc = zmq_close (connectSocket);
    assert (rc == 0);

    rc = zmq_close (bindSocket);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);
}

void test_multiple_connects ()
{
    const unsigned int no_of_connects = 10;
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    int rc;
    void *connectSocket [no_of_connects];

    // Connect first
    for (unsigned int i = 0; i < no_of_connects; ++i)
    {
        connectSocket [i] = zmq_socket (ctx, ZMQ_PUSH);
        assert (connectSocket [i]);
        rc = zmq_connect (connectSocket [i], "inproc://multiple");
        assert (rc == 0);

        // Queue up some data
        rc = zmq_send_const (connectSocket [i], "foobar", 6, 0);
        assert (rc == 6);
    }

    // Now bind
    void *bindSocket = zmq_socket (ctx, ZMQ_PULL);
    assert (bindSocket);
    rc = zmq_bind (bindSocket, "inproc://multiple");
    assert (rc == 0);

    for (unsigned int i = 0; i < no_of_connects; ++i)
    {
        // Read pending message
        zmq_msg_t msg;
        rc = zmq_msg_init (&msg);
        assert (rc == 0);
        rc = zmq_msg_recv (&msg, bindSocket, 0);
        assert (rc == 6);
        void *data = zmq_msg_data (&msg);
        assert (memcmp ("foobar", data, 6) == 0);
    }

    // Cleanup
    for (unsigned int i = 0; i < no_of_connects; ++i)
    {
        rc = zmq_close (connectSocket [i]);
        assert (rc == 0);
    }

    rc = zmq_close (bindSocket);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);
}

void test_multiple_threads ()
{
    const unsigned int no_of_threads = 30;
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    int rc;
    void *threads [no_of_threads];

    // Connect first
    for (unsigned int i = 0; i < no_of_threads; ++i)
    {
        threads [i] = zmq_threadstart (&pusher, ctx);
    }

    // Now bind
    void *bindSocket = zmq_socket (ctx, ZMQ_PULL);
    assert (bindSocket);
    rc = zmq_bind (bindSocket, "inproc://sink");
    assert (rc == 0);

    for (unsigned int i = 0; i < no_of_threads; ++i)
    {
        // Read pending message
        zmq_msg_t msg;
        rc = zmq_msg_init (&msg);
        assert (rc == 0);
        rc = zmq_msg_recv (&msg, bindSocket, 0);
        assert (rc == 6);
        void *data = zmq_msg_data (&msg);
        assert (memcmp ("foobar", data, 6) == 0);
    }

    // Cleanup
    for (unsigned int i = 0; i < no_of_threads; ++i)
    {
        zmq_threadclose (threads [i]);
    }

    rc = zmq_close (bindSocket);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);
}

void test_simultaneous_connect_bind_threads ()
{
    const unsigned int no_of_times = 50;
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    void *threads[no_of_times*2];
    void *thr_args[no_of_times][2];
    char endpts[no_of_times][20];

    // Set up thread arguments: context followed by endpoint string
    for (unsigned int i = 0; i < no_of_times; ++i)
    {
        thr_args[i][0] = (void*) ctx;
        thr_args[i][1] = (void*) endpts[i];
        sprintf (endpts[i], "inproc://foo_%d", i);
    }

    // Spawn all threads as simultaneously as possible
    for (unsigned int i = 0; i < no_of_times; ++i)
    {
        threads[i*2+0] = zmq_threadstart (&simult_conn, (void*)thr_args[i]);
        threads[i*2+1] = zmq_threadstart (&simult_bind, (void*)thr_args[i]);
    }

    // Close all threads
    for (unsigned int i = 0; i < no_of_times; ++i)
    {
        zmq_threadclose (threads[i*2+0]);
        zmq_threadclose (threads[i*2+1]);
    }

    int rc = zmq_ctx_term (ctx);
    assert (rc == 0);
}

void test_identity ()
{
    //  Create the infrastructure
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    void *sc = zmq_socket (ctx, ZMQ_DEALER);
    assert (sc);

    int rc = zmq_connect (sc, "inproc://identity");
    assert (rc == 0);

    void *sb = zmq_socket (ctx, ZMQ_ROUTER);
    assert (sb);

    rc = zmq_bind (sb, "inproc://identity");
    assert (rc == 0);

    //  Send 2-part message.
    rc = zmq_send (sc, "A", 1, ZMQ_SNDMORE);
    assert (rc == 1);
    rc = zmq_send (sc, "B", 1, 0);
    assert (rc == 1);

    //  Identity comes first.
    zmq_msg_t msg;
    rc = zmq_msg_init (&msg);
    assert (rc == 0);
    rc = zmq_msg_recv (&msg, sb, 0);
    assert (rc >= 0);
    int more = zmq_msg_more (&msg);
    assert (more == 1);

    //  Then the first part of the message body.
    rc = zmq_msg_recv (&msg, sb, 0);
    assert (rc == 1);
    more = zmq_msg_more (&msg);
    assert (more == 1);

    //  And finally, the second part of the message body.
    rc = zmq_msg_recv (&msg, sb, 0);
    assert (rc == 1);
    more = zmq_msg_more (&msg);
    assert (more == 0);

    //  Deallocate the infrastructure.
    rc = zmq_close (sc);
    assert (rc == 0);

    rc = zmq_close (sb);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);
}

void test_connect_only ()
{
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    void *connectSocket = zmq_socket (ctx, ZMQ_PUSH);
    assert (connectSocket);
    int rc = zmq_connect (connectSocket, "inproc://a");
    assert (rc == 0);

    rc = zmq_close (connectSocket);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);
}


void test_unbind ()
{
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    // Bind and unbind socket 1
    void *bindSocket1 = zmq_socket (ctx, ZMQ_PAIR);
    assert (bindSocket1);
    int rc = zmq_bind (bindSocket1, "inproc://unbind");
    assert (rc == 0);
    zmq_unbind (bindSocket1, "inproc://unbind");
    assert (rc == 0);

    // Bind socket 2
    void *bindSocket2 = zmq_socket (ctx, ZMQ_PAIR);
    assert (bindSocket2);
    rc = zmq_bind (bindSocket2, "inproc://unbind");
    assert (rc == 0);

    // Now connect
    void *connectSocket = zmq_socket (ctx, ZMQ_PAIR);
    assert (connectSocket);
    rc = zmq_connect (connectSocket, "inproc://unbind");
    assert (rc == 0);

    // Queue up some data
    rc = zmq_send_const (connectSocket, "foobar", 6, 0);
    assert (rc == 6);

    // Read pending message
    zmq_msg_t msg;
    rc = zmq_msg_init (&msg);
    assert (rc == 0);
    rc = zmq_msg_recv (&msg, bindSocket2, 0);
    assert (rc == 6);
    void *data = zmq_msg_data (&msg);
    assert (memcmp ("foobar", data, 6) == 0);

    // Cleanup
    rc = zmq_close (connectSocket);
    assert (rc == 0);
    rc = zmq_close (bindSocket1);
    assert (rc == 0);
    rc = zmq_close (bindSocket2);
    assert (rc == 0);
    rc = zmq_ctx_term (ctx);
    assert (rc == 0);
}

int main (void)
{
    setup_test_environment ();

    test_bind_before_connect ();
    test_connect_before_bind ();
    test_connect_before_bind_pub_sub ();
    test_multiple_connects ();
    test_multiple_threads ();
    test_simultaneous_connect_bind_threads ();
    test_identity ();
    test_connect_only ();
    test_unbind ();

    return 0;
}
