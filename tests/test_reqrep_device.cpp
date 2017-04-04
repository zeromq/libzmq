/*
    Copyright (c) 2007-2016 Contributors as noted in the AUTHORS file

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

int main (void)
{
    setup_test_environment();
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    //  Create a req/rep device.
    void *dealer = zmq_socket (ctx, ZMQ_DEALER);
    assert (dealer);
    int rc = zmq_bind (dealer, "tcp://127.0.0.1:5560");
    assert (rc == 0);
    void *router = zmq_socket (ctx, ZMQ_ROUTER);
    assert (router);
    rc = zmq_bind (router, "tcp://127.0.0.1:5561");
    assert (rc == 0);

    //  Create a worker.
    void *rep = zmq_socket (ctx, ZMQ_REP);
    assert (rep);
    rc = zmq_connect (rep, "tcp://127.0.0.1:5560");
    assert (rc == 0);

    //  Create a client.
    void *req = zmq_socket (ctx, ZMQ_REQ);
    assert (req);
    rc = zmq_connect (req, "tcp://127.0.0.1:5561");
    assert (rc == 0);

    //  Send a request.
    rc = zmq_send (req, "ABC", 3, ZMQ_SNDMORE);
    assert (rc == 3);
    rc = zmq_send (req, "DEF", 3, 0);
    assert (rc == 3);

    //  Pass the request through the device.
    for (int i = 0; i != 4; i++) {
        zmq_msg_t msg;
        rc = zmq_msg_init (&msg);
        assert (rc == 0);
        rc = zmq_msg_recv (&msg, router, 0);
        assert (rc >= 0);
        int rcvmore;
        size_t sz = sizeof (rcvmore);
        rc = zmq_getsockopt (router, ZMQ_RCVMORE, &rcvmore, &sz);
        assert (rc == 0);
        rc = zmq_msg_send (&msg, dealer, rcvmore? ZMQ_SNDMORE: 0);
        assert (rc >= 0);
    }

    //  Receive the request.
    char buff [3];
    rc = zmq_recv (rep, buff, 3, 0);
    assert (rc == 3);
    assert (memcmp (buff, "ABC", 3) == 0);
    int rcvmore;
    size_t sz = sizeof (rcvmore);
    rc = zmq_getsockopt (rep, ZMQ_RCVMORE, &rcvmore, &sz);
    assert (rc == 0);
    assert (rcvmore);
    rc = zmq_recv (rep, buff, 3, 0);
    assert (rc == 3);
    assert (memcmp (buff, "DEF", 3) == 0);
    rc = zmq_getsockopt (rep, ZMQ_RCVMORE, &rcvmore, &sz);
    assert (rc == 0);
    assert (!rcvmore);

    //  Send the reply.
    rc = zmq_send (rep, "GHI", 3, ZMQ_SNDMORE);
    assert (rc == 3);
    rc = zmq_send (rep, "JKL", 3, 0);
    assert (rc == 3);

    //  Pass the reply through the device.
    for (int i = 0; i != 4; i++) {
        zmq_msg_t msg;
        rc = zmq_msg_init (&msg);
        assert (rc == 0);
        rc = zmq_msg_recv (&msg, dealer, 0);
        assert (rc >= 0);
        int rcvmore;
        rc = zmq_getsockopt (dealer, ZMQ_RCVMORE, &rcvmore, &sz);
        assert (rc == 0);
        rc = zmq_msg_send (&msg, router, rcvmore? ZMQ_SNDMORE: 0);
        assert (rc >= 0);
    }

    //  Receive the reply.
    rc = zmq_recv (req, buff, 3, 0);
    assert (rc == 3);
    assert (memcmp (buff, "GHI", 3) == 0);
    rc = zmq_getsockopt (req, ZMQ_RCVMORE, &rcvmore, &sz);
    assert (rc == 0);
    assert (rcvmore);
    rc = zmq_recv (req, buff, 3, 0);
    assert (rc == 3);
    assert (memcmp (buff, "JKL", 3) == 0);
    rc = zmq_getsockopt (req, ZMQ_RCVMORE, &rcvmore, &sz);
    assert (rc == 0);
    assert (!rcvmore);

    //  Clean up.
    rc = zmq_close (req);
    assert (rc == 0);
    rc = zmq_close (rep);
    assert (rc == 0);
    rc = zmq_close (router);
    assert (rc == 0);
    rc = zmq_close (dealer);
    assert (rc == 0);
    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    return 0 ;
}
