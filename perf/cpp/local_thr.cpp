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

#include <zmq.hpp>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/time.h>

int main (int argc, char *argv [])
{
    if (argc != 4) {
        printf ("usage: local_thr <bind-to> <message-count> "
            "<message-size>\n");
        return 1;
    }
    const char *bind_to = argv [1];
    int message_count = atoi (argv [2]);
    size_t message_size = (size_t) atoi (argv [3]);

    zmq::context_t ctx (1, 1);

    zmq::socket_t s (ctx, ZMQ_P2P);
    s.bind (bind_to);

    zmq::message_t msg;
    s.recv (&msg);
    assert (msg.size () == message_size);

    timeval start;
    int rc = gettimeofday (&start, NULL);
    assert (rc == 0);

    for (int i = 0; i != message_count - 1; i++) {
        s.recv (&msg);
        assert (msg.size () == message_size);
    }

    timeval end;
    rc = gettimeofday (&end, NULL);
    assert (rc == 0);

    end.tv_sec -= start.tv_sec;
    start.tv_sec = 0;

    uint64_t elapsed = ((uint64_t) end.tv_sec * 1000000 + end.tv_usec) -
        ((uint64_t) start.tv_sec * 1000000 + start.tv_usec);

    uint64_t throughput = (uint64_t) message_count * 1000000 / elapsed;

    printf ("message size: %d [B]\n", (int) message_size);
    printf ("message count: %d\n", (int) message_count);
    printf ("mean throughput: %d [msg/s]\n", (int) throughput);

    return 0;
}
