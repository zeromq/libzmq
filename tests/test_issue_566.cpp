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

#include "testutil.hpp"

//  Issue 566 describes a problem in libzmq v4.0.0 where a dealer to router
//  connection would fail randomly. The test works when the two sockets are
//  on the same context, and failed when they were on separate contexts.
//  Fixed by https://github.com/zeromq/libzmq/commit/be25cf.

int main (void)
{
    setup_test_environment();
    
    void *ctx1 = zmq_ctx_new ();
    assert (ctx1);

    void *ctx2 = zmq_ctx_new ();
    assert (ctx2);

    void *router = zmq_socket (ctx1, ZMQ_ROUTER);    
    int on = 1;
    int rc = zmq_setsockopt (router, ZMQ_ROUTER_MANDATORY, &on, sizeof (on));
    assert (rc == 0);
    rc = zmq_bind (router, "tcp://127.0.0.1:5555");
    assert (rc != -1);
 
    //  Repeat often enough to be sure this works as it should
    for (int cycle = 0; cycle < 100; cycle++) {
        //  Create dealer with unique explicit identity
        //  We assume the router learns this out-of-band
        void *dealer = zmq_socket (ctx2, ZMQ_DEALER);
        char identity [10];
        sprintf (identity, "%09d", cycle);
        rc = zmq_setsockopt (dealer, ZMQ_IDENTITY, identity, 10);
        assert (rc == 0);
        int rcvtimeo = 1000;
        rc = zmq_setsockopt (dealer, ZMQ_RCVTIMEO, &rcvtimeo, sizeof (int));
        assert (rc == 0);
        rc = zmq_connect (dealer, "tcp://127.0.0.1:5555");
        assert (rc == 0);

        //  Router will try to send to dealer, at short intervals.
        //  It typically takes 2-5 msec for the connection to establish
        //  on a loopback interface, but we'll allow up to one second
        //  before failing the test (e.g. for running on a debugger or
        //  a very slow system).
        for (int attempt = 0; attempt < 500; attempt++) {
            zmq_poll (0, 0, 2);
            rc = zmq_send (router, identity, 10, ZMQ_SNDMORE);
            if (rc == -1 && errno == EHOSTUNREACH)
                continue;
            assert (rc == 10);
            rc = zmq_send (router, "HELLO", 5, 0);
            assert (rc == 5);
            break;
        }
        uint8_t buffer [5];
        rc = zmq_recv (dealer, buffer, 5, 0);
        assert (rc == 5);
        assert (memcmp (buffer, "HELLO", 5) == 0);
        close_zero_linger (dealer);
    }
    zmq_close (router);
    zmq_ctx_destroy (ctx1);
    zmq_ctx_destroy (ctx2);

    return 0;
}
