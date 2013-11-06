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

int main (void)
{
    setup_test_environment();
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    //  First, create an intermediate device
    void *xpub = zmq_socket (ctx, ZMQ_XPUB);
    assert (xpub);
    int rc = zmq_bind (xpub, "tcp://127.0.0.1:5560");
    assert (rc == 0);
    void *xsub = zmq_socket (ctx, ZMQ_XSUB);
    assert (xsub);
    rc = zmq_bind (xsub, "tcp://127.0.0.1:5561");
    assert (rc == 0);

    //  Create a publisher
    void *pub = zmq_socket (ctx, ZMQ_PUB);
    assert (pub);
    rc = zmq_connect (pub, "tcp://127.0.0.1:5561");
    assert (rc == 0);

    //  Create a subscriber
    void *sub = zmq_socket (ctx, ZMQ_SUB);
    assert (sub);
    rc = zmq_connect (sub, "tcp://127.0.0.1:5560");
    assert (rc == 0);

    //  Subscribe for all messages.
    rc = zmq_setsockopt (sub, ZMQ_SUBSCRIBE, "", 0);
    assert (rc == 0);

    //  Pass the subscription upstream through the device
    char buff [32];
    rc = zmq_recv (xpub, buff, sizeof (buff), 0);
    assert (rc >= 0);
    rc = zmq_send (xsub, buff, rc, 0);
    assert (rc >= 0);

    //  Wait a bit till the subscription gets to the publisher
    msleep (SETTLE_TIME);

    //  Send an empty message
    rc = zmq_send (pub, NULL, 0, 0);
    assert (rc == 0);

    //  Pass the message downstream through the device
    rc = zmq_recv (xsub, buff, sizeof (buff), 0);
    assert (rc >= 0);
    rc = zmq_send (xpub, buff, rc, 0);
    assert (rc >= 0);

    //  Receive the message in the subscriber
    rc = zmq_recv (sub, buff, sizeof (buff), 0);
    assert (rc == 0);

    //  Clean up.
    rc = zmq_close (xpub);
    assert (rc == 0);
    rc = zmq_close (xsub);
    assert (rc == 0);
    rc = zmq_close (pub);
    assert (rc == 0);
    rc = zmq_close (sub);
    assert (rc == 0);
    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    return 0 ;
}
