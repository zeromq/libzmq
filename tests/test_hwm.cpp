/*
    Copyright (c) 2010-2011 250bpm s.r.o.
    Copyright (c) 2010-2011 Other contributors as noted in the AUTHORS file

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


#include <stdio.h>
#include "testutil.hpp"

int main (void)
{
    fprintf (stderr, "test_hwm running...\n");

    void *ctx = zmq_init (1);
    assert (ctx);

    //  Create pair of socket, each with high watermark of 2. Thus the total
    //  buffer space should be 4 messages.
    void *sb = zmq_socket (ctx, ZMQ_PULL);
    assert (sb);
    int hwm = 2;
    int rc = zmq_setsockopt (sb, ZMQ_RCVHWM, &hwm, sizeof (hwm));
    assert (rc == 0);
    rc = zmq_bind (sb, "inproc://a");
    assert (rc == 0);

    void *sc = zmq_socket (ctx, ZMQ_PUSH);
    assert (sc);
    rc = zmq_setsockopt (sc, ZMQ_SNDHWM, &hwm, sizeof (hwm));
    assert (rc == 0);
    rc = zmq_connect (sc, "inproc://a");
    assert (rc == 0);

    //  Try to send 10 messages. Only 4 should succeed.
    for (int i = 0; i < 10; i++)
    {
        int rc = zmq_send (sc, NULL, 0, ZMQ_DONTWAIT);
        if (i < 4)
            assert (rc == 0);
        else
            assert (rc < 0 && errno == EAGAIN);
    }

    // There should be now 4 messages pending, consume them.
    for (int i = 0; i != 4; i++) {
        rc = zmq_recv (sb, NULL, 0, 0);
        assert (rc == 0);
    }

    // Now it should be possible to send one more.
    rc = zmq_send (sc, NULL, 0, 0);
    assert (rc == 0);

    //  Consume the remaining message.
    rc = zmq_recv (sb, NULL, 0, 0);
    assert (rc == 0);

    rc = zmq_close (sc);
    assert (rc == 0);

    rc = zmq_close (sb);
    assert (rc == 0);

    rc = zmq_term (ctx);
    assert (rc == 0);

	return 0;
}
