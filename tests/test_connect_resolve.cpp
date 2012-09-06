/*
    Copyright (c) 2012 Spotify AB
    Copyright (c) 2012 Other contributors as noted in the AUTHORS file

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

#include "../include/zmq.h"
#include <stdio.h>
#include <errno.h>

#undef NDEBUG
#include <assert.h>

int main (void)
{
    fprintf (stderr, "test_connect_resolve running...\n");

    void *ctx = zmq_init (1);
    assert (ctx);

    //  Create pair of socket, each with high watermark of 2. Thus the total
    //  buffer space should be 4 messages.
    void *sock = zmq_socket (ctx, ZMQ_PUB);
    assert (sock);

    int rc = zmq_connect (sock, "tcp://localhost:1234");
    assert (rc == 0);

    rc = zmq_connect (sock, "tcp://0mq.is.teh.best:1234");
    assert (rc == -1);
    assert (errno == EINVAL);

    rc = zmq_close (sock);
    assert (rc == 0);

    rc = zmq_term (ctx);
    assert (rc == 0);

    return 0;
}
