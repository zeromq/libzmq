/*
    Copyright (c) 2007-2009 FastMQ Inc.

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the Lesser GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    Lesser GNU General Public License for more details.

    You should have received a copy of the Lesser GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <zmq.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/time.h>

int main (int argc, char *argv [])
{
    const char *connect_to;
    int roundtrip_count;
    int message_size;
    void *ctx;
    void *s;
    int rc;
    int i;
    struct zmq_msg_t msg;
    struct timeval start;
    struct timeval end;
    double elapsed;
    double latency;

    if (argc != 4) {
        printf ("usage: remote_lat <connect-to> <roundtrip-count> "
            "<message-size>\n");
        return 1;
    }
    connect_to = argv [1];
    roundtrip_count = atoi (argv [2]);
    message_size = atoi (argv [3]);

    ctx = zmq_init (1, 1);
    assert (ctx);

    s = zmq_socket (ctx, ZMQ_REQ);
    assert (s);

    rc = zmq_connect (s, connect_to);
    assert (rc == 0);

    rc = gettimeofday (&start, NULL);
    assert (rc == 0);

    rc = zmq_msg_init_size (&msg, message_size);
    assert (rc == 0);

    for (i = 0; i != roundtrip_count; i++) {
        rc = zmq_send (s, &msg, 0);
        assert (rc == 0);
        rc = zmq_recv (s, &msg, 0);
        assert (rc == 0);
        assert (zmq_msg_size (&msg) == message_size);
    }

    rc = zmq_msg_close (&msg);
    assert (rc == 0);

    rc = gettimeofday (&end, NULL);
    assert (rc == 0);

    end.tv_sec -= start.tv_sec;
    start.tv_sec = 0;

    elapsed = (end.tv_sec * 1000000 + end.tv_usec) -
        (start.tv_sec * 1000000 + start.tv_usec);
    latency = elapsed / (roundtrip_count * 2);

    printf ("message size: %d [B]\n", (int) message_size);
    printf ("roundtrip count: %d\n", (int) roundtrip_count);
    printf ("average latency: %.3f [us]\n", (double) latency);

    rc = zmq_term (ctx);
    assert (rc == 0);

    return 0;
}
