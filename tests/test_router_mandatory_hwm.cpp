/*
    Copyright (c) 2007-2017 Contributors as noted in the AUTHORS file

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

// DEBUG shouldn't be defined in sources as it will cause a redefined symbol
// error when it is defined in the build configuration. It appears that the
// intent here is to semi-permanently disable DEBUG tracing statements, so the
// implementation is changed to accomodate that intent.
//#define DEBUG 0
#define TRACE_ENABLED 0

int main (void)
{
    int rc;
    if (TRACE_ENABLED) fprintf(stderr, "Staring router mandatory HWM test ...\n");
    setup_test_environment();
    size_t len = MAX_SOCKET_STRING;
    char my_endpoint[MAX_SOCKET_STRING];
    void *ctx = zmq_ctx_new ();
    assert (ctx);
    void *router = zmq_socket (ctx, ZMQ_ROUTER);
    assert (router);

    // Configure router socket to mandatory routing and set HWM and linger
    int mandatory = 1;
    rc = zmq_setsockopt (router, ZMQ_ROUTER_MANDATORY, &mandatory, sizeof (mandatory));
    assert (rc == 0);
    int sndhwm = 1;
    rc = zmq_setsockopt (router, ZMQ_SNDHWM, &sndhwm, sizeof (sndhwm));
    assert (rc == 0);
    int linger = 1;
    rc = zmq_setsockopt (router, ZMQ_LINGER, &linger, sizeof (linger));
    assert (rc == 0);

    rc = zmq_bind (router, "tcp://127.0.0.1:*");
    assert (rc == 0);
    rc = zmq_getsockopt (router, ZMQ_LAST_ENDPOINT, my_endpoint, &len);
    assert (rc == 0);

    //  Create dealer called "X" and connect it to our router, configure HWM
    void *dealer = zmq_socket (ctx, ZMQ_DEALER);
    assert (dealer);
    rc = zmq_setsockopt (dealer, ZMQ_IDENTITY, "X", 1);
    assert (rc == 0);
    int rcvhwm = 1;
    rc = zmq_setsockopt (dealer, ZMQ_RCVHWM, &rcvhwm, sizeof (rcvhwm));
    assert (rc == 0);

    rc = zmq_connect (dealer, my_endpoint);
    assert (rc == 0);

    //  Get message from dealer to know when connection is ready
    char buffer [255];
    rc = zmq_send (dealer, "Hello", 5, 0);
    assert (rc == 5);
    rc = zmq_recv (router, buffer, 255, 0);
    assert (rc == 1);
    assert (buffer [0] ==  'X');

    int i;
    const int BUF_SIZE = 65536;
    char buf[BUF_SIZE];
    memset(buf, 0, BUF_SIZE);
    // Send first batch of messages
    for(i = 0; i < 100000; ++i) {
        if (TRACE_ENABLED) fprintf(stderr, "Sending message %d ...\n", i);
        rc = zmq_send (router, "X", 1, ZMQ_DONTWAIT | ZMQ_SNDMORE);
        if (rc == -1 && zmq_errno() == EAGAIN) break;
        assert (rc == 1);
        rc = zmq_send (router, buf, BUF_SIZE, ZMQ_DONTWAIT);
        assert (rc == BUF_SIZE);
    }
    // This should fail after one message but kernel buffering could
    // skew results
    assert (i < 10);
    msleep (1000);
    // Send second batch of messages
    for(; i < 100000; ++i) {
        if (TRACE_ENABLED) fprintf(stderr, "Sending message %d (part 2) ...\n", i);
        rc = zmq_send (router, "X", 1, ZMQ_DONTWAIT | ZMQ_SNDMORE);
        if (rc == -1 && zmq_errno() == EAGAIN) break;
        assert (rc == 1);
        rc = zmq_send (router, buf, BUF_SIZE, ZMQ_DONTWAIT);
        assert (rc == BUF_SIZE);
    }
    // This should fail after two messages but kernel buffering could
    // skew results
    assert (i < 20);

    if (TRACE_ENABLED) fprintf(stderr, "Done sending messages.\n");

    rc = zmq_close (router);
    assert (rc == 0);

    rc = zmq_close (dealer);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    return 0 ;
}
