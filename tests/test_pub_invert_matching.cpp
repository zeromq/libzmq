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

    //  Create a publisher
    void *pub = zmq_socket (ctx, ZMQ_PUB);
    assert (pub);
    int rc = zmq_bind (pub, "inproc://soname");
    assert (rc == 0);

    //  Create two subscribers
    void *sub1 = zmq_socket (ctx, ZMQ_SUB);
    assert (sub1);
    rc = zmq_connect (sub1, "inproc://soname");
    assert (rc == 0);

    void *sub2 = zmq_socket (ctx, ZMQ_SUB);
    assert (sub2);
    rc = zmq_connect (sub2, "inproc://soname");
    assert (rc == 0);

    //  Subscribe pub1 to one prefix
    //  and pub2 to another prefix.
    const char PREFIX1[] = "prefix1";
    const char PREFIX2[] = "p2";

    rc = zmq_setsockopt (sub1, ZMQ_SUBSCRIBE, PREFIX1, sizeof(PREFIX1));
    assert (rc == 0);

    rc = zmq_setsockopt (sub2, ZMQ_SUBSCRIBE, PREFIX2, sizeof(PREFIX2));
    assert (rc == 0);

    //  Send a message with the first prefix
    rc = zmq_send_const(pub, PREFIX1, sizeof(PREFIX1), 0);
    assert (rc == sizeof(PREFIX1));

    //  sub1 should receive it, but not sub2
    rc = zmq_recv (sub1, NULL, 0, ZMQ_DONTWAIT);
    assert (rc == sizeof(PREFIX1));

    rc = zmq_recv (sub2, NULL, 0, ZMQ_DONTWAIT);
    assert (rc == -1);
    assert (errno == EAGAIN);

    //  Send a message with the second prefix
    rc = zmq_send_const(pub, PREFIX2, sizeof(PREFIX2), 0);
    assert (rc == sizeof(PREFIX2));

    //  sub2 should receive it, but not sub1
    rc = zmq_recv (sub2, NULL, 0, ZMQ_DONTWAIT);
    assert (rc == sizeof(PREFIX2));

    rc = zmq_recv (sub1, NULL, 0, ZMQ_DONTWAIT);
    assert (rc == -1);
    assert (errno == EAGAIN);

    //  Now invert the matching
    int invert = 1;
    rc = zmq_setsockopt (pub, ZMQ_INVERT_MATCHING, &invert, sizeof(invert));
    assert (rc == 0);

    //  ... on both sides, otherwise the SUB socket will filter the messages out
    rc = zmq_setsockopt (sub1, ZMQ_INVERT_MATCHING, &invert, sizeof(invert));
    rc = zmq_setsockopt (sub2, ZMQ_INVERT_MATCHING, &invert, sizeof(invert));
    assert (rc == 0);

    //  Send a message with the first prefix
    rc = zmq_send_const(pub, PREFIX1, sizeof(PREFIX1), 0);
    assert (rc == sizeof(PREFIX1));

    //  sub2 should receive it, but not sub1
    rc = zmq_recv (sub2, NULL, 0, ZMQ_DONTWAIT);
    assert (rc == sizeof(PREFIX1));

    rc = zmq_recv (sub1, NULL, 0, ZMQ_DONTWAIT);
    assert (rc == -1);
    assert (errno == EAGAIN);

    //  Send a message with the second prefix
    rc = zmq_send_const(pub, PREFIX2, sizeof(PREFIX2), 0);
    assert (rc == sizeof(PREFIX2));

    //  sub1 should receive it, but not sub2
    rc = zmq_recv (sub1, NULL, 0, ZMQ_DONTWAIT);
    assert (rc == sizeof(PREFIX2));

    rc = zmq_recv (sub2, NULL, 0, ZMQ_DONTWAIT);
    assert (rc == -1);
    assert (errno == EAGAIN);


    //  Clean up.
    rc = zmq_close (pub);
    assert (rc == 0);
    rc = zmq_close (sub1);
    assert (rc == 0);
    rc = zmq_close (sub2);
    assert (rc == 0);
    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    return 0 ;
}
