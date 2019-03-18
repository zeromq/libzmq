/*
    Copyright (c) 2007-2019 Contributors as noted in the AUTHORS file

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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

#include "testutil.hpp"

int main(int argc, char **argv)
{
	char my_endpoint[1024];
	char buffer[255];
	int flag, rc, i;
	size_t len;

	void *dealer_one, *dealer_two;
	void *router;
	void *ctx;

	len = sizeof(my_endpoint);

	ctx = zmq_ctx_new();
	assert(ctx);

	router = zmq_socket(ctx, ZMQ_ROUTER);
	assert(router);

	flag = 0;
	rc = zmq_setsockopt(router, ZMQ_LINGER, &flag, sizeof(flag));
	assert(rc == 0);

	// Enable the handover flag
	flag = 1;
	rc = zmq_setsockopt(router, ZMQ_ROUTER_HANDOVER, &flag, sizeof(flag));
	assert(rc == 0);

	rc = zmq_bind(router, "tcp://127.0.0.1:5555");
	assert(rc == 0);

	rc = zmq_getsockopt(router, ZMQ_LAST_ENDPOINT, my_endpoint, &len);
	assert(rc == 0);

	//  Create dealer called "X" and connect it to our router
	dealer_one = zmq_socket(ctx, ZMQ_DEALER);
	assert(dealer_one);

	flag = 0;
	rc = zmq_setsockopt(dealer_one, ZMQ_LINGER, &flag, sizeof(flag));
	assert(rc == 0);


	rc = zmq_setsockopt(dealer_one, ZMQ_IDENTITY, "X", 1);
	assert(rc == 0);

	rc = zmq_connect(dealer_one, my_endpoint);
	assert(rc == 0);

	for (i = 0; i < 5000; i++) {
		//  Get message from dealer to know when connection is ready
		rc = zmq_send(dealer_one, "Hello", 5, 0);
		assert(rc == 5);

		rc = zmq_recv(router, buffer, sizeof(buffer), 0);
		assert(rc == 1);
		assert(memcmp(buffer, "X", 1) == 0);

		rc = zmq_recv(router, buffer, sizeof(buffer), 0);
		assert(rc == 5);
		assert(memcmp(buffer, "Hello", 5) == 0);

		// Now create a second dealer that uses the same routing id
		dealer_two = zmq_socket(ctx, ZMQ_DEALER);
		assert(dealer_two);

		flag = 0;
		rc = zmq_setsockopt(dealer_two, ZMQ_LINGER, &flag, sizeof(flag));
		assert(rc == 0);

		rc = zmq_setsockopt(dealer_two, ZMQ_IDENTITY, "X", 1);
		assert(rc == 0);

		rc = zmq_connect(dealer_two, my_endpoint);
		assert(rc == 0);

		//  Get message from dealer to know when connection is ready
		rc = zmq_send(dealer_two, "Hello", 5, 0);
		assert(rc == 5);

		// Receive on router only first message
		rc = zmq_recv(router, buffer, sizeof(buffer), 0);
		assert(rc == 1);
		assert(memcmp(buffer, "X", 1) == 0);

		rc = zmq_recv(router, buffer, sizeof(buffer), 0);
		assert(rc == 5);
		assert(memcmp(buffer, "Hello", 5) == 0);

		//
		// Send from dealer which is inactive now, message should
		// not be received, but on router side descriptor leaks !!!!!!
		// see issue #3238
		//
		rc = zmq_send(dealer_one, "Hello", 5, 0);
		assert(rc == 5);

		// Roll to the active dealer
		zmq_close(dealer_one);
		dealer_one = dealer_two;

		// Count number of opened descriptors each thousand
#ifdef ZMQ_HAVE_LINUX
		if (i && 0 == i % 1000) {
			FILE *fp;

			snprintf(buffer, sizeof(buffer), "ls -la /proc/%d/fd | wc -l",
				 getpid());
			fp = popen(buffer, "r");
			assert(fp);

			rc = fread(buffer, 1, sizeof(buffer)-1, fp);
			assert(rc > 0 && rc < 10);
			buffer[rc-1] = 0;

			printf("Total fds: %s\n", buffer);
			pclose(fp);
		}
#endif
	}

	// If we reach this line we have not crashed, so everything is fine
	printf("OK\n");

	return 0;
}
