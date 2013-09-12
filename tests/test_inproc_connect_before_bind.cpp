/*
    Copyright (c) 2007-2013 Contributors as noted in the AUTHORS file

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

#include <stdio.h>
#include "testutil.hpp"

void test_bind_before_connect()
{
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    // Bind first
    void *bindSocket = zmq_socket (ctx, ZMQ_PAIR);
    assert (bindSocket);
    int rc = zmq_bind (bindSocket, "inproc://a");
    assert (rc == 0);

    // Now connect
    void *connectSocket = zmq_socket (ctx, ZMQ_PAIR);
    assert (connectSocket);
    rc = zmq_connect (connectSocket, "inproc://a");
    assert (rc == 0);
    
    // Queue up some data
    rc = zmq_send_const (connectSocket, "foobar", 6, 0);
    assert (rc == 6);

    // Read pending message
    zmq_msg_t msg;
    rc = zmq_msg_init (&msg);
    assert (rc == 0);
    rc = zmq_msg_recv (&msg, bindSocket, ZMQ_NOBLOCK);
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

void test_connect_before_bind()
{
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    // Connect first
    void *connectSocket = zmq_socket (ctx, ZMQ_PAIR);
    assert (connectSocket);
    int rc = zmq_connect (connectSocket, "inproc://a");
    assert (rc == 0);


    // Queue up some data
    rc = zmq_send_const (connectSocket, "foobar", 6, 0);
    assert (rc == 6);

    // Now bind
    void *bindSocket = zmq_socket (ctx, ZMQ_PAIR);
    assert (bindSocket);
    rc = zmq_bind (bindSocket, "inproc://a");
    assert (rc == 0);
    
    // Read pending message
    zmq_msg_t msg;
    rc = zmq_msg_init (&msg);
    assert (rc == 0);
    rc = zmq_msg_recv (&msg, bindSocket, ZMQ_NOBLOCK);
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

int main (void)
{
    setup_test_environment();

    test_bind_before_connect();
    test_connect_before_bind();

    return 0 ;
}
