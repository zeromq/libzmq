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

//  This test case should be moved or added to issues repository, perhaps,
//  or alternatively we can change policy that issue test cases should be 
//  added to the main build when they're useful. -- PH 2013/09/02

#include "testutil.hpp"

#define URL "tcp://127.0.0.1:5560"

//  Sender connects a PUSH socket and sends a message of a given size,
//  closing the socket and terminating the context immediately.
//  LINGER should prevent this from dropping messages.

static void sender (void *vsize)
{
    void *context = zmq_ctx_new ();
    void *push = zmq_socket (context, ZMQ_PUSH);
    size_t size = ((size_t *) vsize) [0];

    int rc = zmq_connect (push, URL);
    assert (rc == 0);
  
    zmq_msg_t msg;
    rc = zmq_msg_init_size (&msg, size);
    assert (rc == 0);

    char *buf = (char *) zmq_msg_data (&msg);
    assert (buf != NULL);
    memset (buf, 'x', size);

    rc = zmq_msg_send (&msg, push, 0);
    assert ((size_t) rc == size);

    rc = zmq_msg_close (&msg);
    assert (rc == 0);

    rc = zmq_close (push);
    assert (rc == 0);

    rc = zmq_ctx_term (context);
    assert (rc == 0);
}

int main (void)
{
    void *context = zmq_ctx_new ();
    void *pull = zmq_socket (context, ZMQ_PULL);
    zmq_msg_t msg;
    
    int rc = zmq_bind (pull, URL);
    assert (rc == 0);
    
    //  Symptom of test failure is message never received
    int rcvtimeo = 100;
    rc = zmq_setsockopt (pull, ZMQ_RCVTIMEO, &rcvtimeo, sizeof (int));
    assert (rc == 0);
    
    //  Single test case that currently provokes failure in libzmq
    //  Note that socket will wait as long as receive timeout, before
    //  returning a "resource unavailable" or an assertion failure in
    //  poller_base.cpp:31.
    size_t size = 4000000;
    
    //  Start the sender thread and get message
    void *send_thread = zmq_threadstart (&sender, (void *) &size);
    zmq_msg_init (&msg);
    rc = zmq_msg_recv (&msg, pull, 0);
    assert ((size_t) rc == size);
    zmq_msg_close (&msg);
    zmq_threadclose (send_thread);
    
    zmq_close (pull);
    zmq_ctx_term (context);
    return 0;
}
