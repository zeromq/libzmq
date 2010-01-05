/*
    Copyright (c) 2007-2010 iMatix Corporation

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

int main (int argc, char *argv [])
{
    const char *bind_to;
    int message_count;
    int message_size;
    void *ctx;
    void *s;
    int rc;
    int i;
    zmq_msg_t msg;
    void *watch;
    unsigned long elapsed;
    unsigned long throughput;
    double megabits;

    if (argc != 4) {
        printf ("usage: local_thr <bind-to> <message-size> <message-count>\n");
        return 1;
    }
    bind_to = argv [1];
    message_size = atoi (argv [2]);
    message_count = atoi (argv [3]);

    ctx = zmq_init (1, 1, 0);
    assert (ctx);

    s = zmq_socket (ctx, ZMQ_SUB);
    assert (s);

    rc = zmq_setsockopt (s, ZMQ_SUBSCRIBE , "", 0);
    assert (rc == 0);

    //  Add your socket options here.
    //  For example ZMQ_RATE, ZMQ_RECOVERY_IVL and ZMQ_MCAST_LOOP for PGM.

    rc = zmq_bind (s, bind_to);
    assert (rc == 0);

    rc = zmq_msg_init (&msg);
    assert (rc == 0);

    rc = zmq_recv (s, &msg, 0);
    assert (rc == 0);
    assert (zmq_msg_size (&msg) == message_size);

    watch = zmq_stopwatch_start ();

    for (i = 0; i != message_count - 1; i++) {
        rc = zmq_recv (s, &msg, 0);
        assert (rc == 0);
        assert (zmq_msg_size (&msg) == message_size);
    }

    elapsed = zmq_stopwatch_stop (watch);
    if (elapsed == 0)
        elapsed = 1;

    rc = zmq_msg_close (&msg);
    assert (rc == 0);

    throughput = (unsigned long)
        ((double) message_count / (double) elapsed * 1000000);
    megabits = (double) (throughput * message_size * 8) / 1000000;

    printf ("message size: %d [B]\n", (int) message_size);
    printf ("message count: %d\n", (int) message_count);
    printf ("mean throughput: %d [msg/s]\n", (int) throughput);
    printf ("mean throughput: %.3f [Mb/s]\n", (double) megabits);

    rc = zmq_close (s);
    assert (rc == 0);

    rc = zmq_term (ctx);
    assert (rc == 0);

    return 0;
}
