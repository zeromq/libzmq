/*
    Copyright (c) 2007-2015 Contributors as noted in the AUTHORS file

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

int main (void)
{
    setup_test_environment();
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    //  Create a publisher
    void *pub = zmq_socket (ctx, ZMQ_XPUB);
    assert (pub);
    int rc = zmq_bind (pub, "inproc://soname");
    assert (rc == 0);

    //  set pub socket options
    int manual = 1;
	rc = zmq_setsockopt(pub, ZMQ_XPUB_MANUAL, &manual, 4);
    assert (rc == 0); 

    //  Create a subscriber
    void *sub = zmq_socket (ctx, ZMQ_XSUB);
    assert (sub);
    rc = zmq_connect (sub, "inproc://soname");
    assert (rc == 0);	
	
    //  Subscribe for A
	char subscription[2] = { 1, 'A'};
	rc = zmq_send_const(sub, subscription, 2, 0);    		
    assert (rc == 2);	

	char buffer[2];
	
	// Receive subscriptions from subscriber
	rc = zmq_recv(pub, buffer, 2, 0);	
	assert(rc == 2);
	assert(buffer[0] == 1);
	assert(buffer[1] == 'A');	

	// Subscribe socket for B instead
	rc = zmq_setsockopt(pub, ZMQ_SUBSCRIBE, "B", 1);
	assert(rc == 0);

	// Sending A message and B Message
	rc = zmq_send_const(pub, "A", 1, 0);
	assert(rc == 1);	

	rc = zmq_send_const(pub, "B", 1, 0);
	assert(rc == 1);		

	rc = zmq_recv(sub, buffer, 1, ZMQ_DONTWAIT);
	assert(rc == 1);
	assert(buffer[0] == 'B');	

    //  Clean up.
    rc = zmq_close (pub);
    assert (rc == 0);
    rc = zmq_close (sub);
    assert (rc == 0);
    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    return 0 ;
}
