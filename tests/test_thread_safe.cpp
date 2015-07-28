/*:
    Copyright (c) 2007-2015 Contributors as noted in the AUTHORS file

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

void worker1(void* s);
void worker2(void* s);

int main (void)
{
    setup_test_environment();
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    void *client = zmq_socket (ctx, ZMQ_CLIENT);
    void *client2 = zmq_socket (ctx, ZMQ_CLIENT);

    int rc;

    rc = zmq_bind (client, "tcp://127.0.0.1:5560");
    assert (rc == 0);

    rc = zmq_connect (client2, "tcp://127.0.0.1:5560");
    assert (rc == 0);

	void*  t1 = zmq_threadstart(worker1, client2);
	void*  t2 = zmq_threadstart(worker2, client2);	

	char data[1];
	data[0] = 0;

	for (int i=0; i < 10; i++) {
		rc = zmq_send_const(client, data, 1, 0);
		assert (rc == 1);

		rc = zmq_send_const(client, data, 1, 0);
		assert(rc == 1);

		char a, b;

		rc = zmq_recv(client, &a, 1, 0);
		assert(rc == 1);

		rc = zmq_recv(client, &b, 1, 0);
		assert(rc == 1);

		// make sure they came from different threads
		assert((a == 1 && b == 2) || (a == 2 && b == 1));
	}

	// make the thread exit
	data[0] = 1;

	rc = zmq_send_const(client, data, 1, 0);
	assert (rc == 1);

	rc = zmq_send_const(client, data, 1, 0);
	assert(rc == 1);

	zmq_threadclose(t1);
	zmq_threadclose(t2);	

    rc = zmq_close (client2);
    assert (rc == 0);

    rc = zmq_close (client);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    return 0 ;
}

void worker1(void* s)
{
	const char worker_id = 1;
	char c;

	while (true)
	{
		int rc = zmq_recv(s, &c,1, 0); 
		assert(rc == 1);

		if (c == 0)
		{
			msleep(100);
			rc = zmq_send_const(s,&worker_id, 1, 0);
			assert(rc == 1);
		}
		else
		{
			// we got exit request
			break;
		}
	}
}

void worker2(void* s)
{
	const char worker_id = 2;
	char c;

	while (true)
	{
		int rc = zmq_recv(s, &c,1, 0); 
		assert(rc == 1);

		assert(c == 1 || c == 0);

		if (c == 0)
		{
			msleep(100);
			rc = zmq_send_const(s,&worker_id, 1, 0);
			assert(rc == 1);
		}
		else
		{
			// we got exit request
			break;
		}
	}
}






