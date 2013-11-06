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
    int rc;
    char buf[32];
    const char *ep = "tcp://127.0.0.1:5560";

    //  Create infrastructure.
    void *ctx = zmq_ctx_new ();
    assert (ctx);
    void *push = zmq_socket (ctx, ZMQ_PUSH);
    assert (push);
    rc = zmq_bind (push, ep);
    assert (rc == 0);
    void *pull = zmq_socket (ctx, ZMQ_PULL);
    assert (pull);
    rc = zmq_connect (pull, ep);
    assert (rc == 0);

    //  Pass one message through to ensure the connection is established
    rc = zmq_send (push, "ABC", 3, 0);
    assert (rc == 3);
    rc = zmq_recv (pull, buf, sizeof (buf), 0);
    assert (rc == 3);

    //  Unbind the listening endpoint
    rc = zmq_unbind (push, ep);
    assert (rc == 0);

    //  Allow unbind to settle
    msleep (SETTLE_TIME);

    //  Check that sending would block (there's no outbound connection)
    rc = zmq_send (push, "ABC", 3, ZMQ_DONTWAIT);
    assert (rc == -1 && zmq_errno () == EAGAIN);

    //  Clean up
    rc = zmq_close (pull);
    assert (rc == 0);
    rc = zmq_close (push);
    assert (rc == 0);
    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    //  Create infrastructure
    ctx = zmq_ctx_new ();
    assert (ctx);
    push = zmq_socket (ctx, ZMQ_PUSH);
    assert (push);
    rc = zmq_connect (push, ep);
    assert (rc == 0);
    pull = zmq_socket (ctx, ZMQ_PULL);
    assert (pull);
    rc = zmq_bind (pull, ep);
    assert (rc == 0);

    //  Pass one message through to ensure the connection is established.
    rc = zmq_send (push, "ABC", 3, 0);
    assert (rc == 3);
    rc = zmq_recv (pull, buf, sizeof (buf), 0);
    assert (rc == 3);

    //  Disconnect the bound endpoint
    rc = zmq_disconnect (push, ep);
    assert (rc == 0);

    //  Allow disconnect to settle
    msleep (SETTLE_TIME);

    //  Check that sending would block (there's no inbound connections).
    rc = zmq_send (push, "ABC", 3, ZMQ_DONTWAIT);
    assert (rc == -1 && zmq_errno () == EAGAIN);

    //  Clean up.
    rc = zmq_close (pull);
    assert (rc == 0);
    rc = zmq_close (push);
    assert (rc == 0);
    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    return 0;
}
