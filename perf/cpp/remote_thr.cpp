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

int main (int argc, char *argv [])
{
    if (argc != 4) {
        printf ("usage: remote_thr <connect-to> <message-size> "
            "<message-count>\n");
        return 1;
    }
    const char *connect_to = argv [1];
    size_t message_size = (size_t) atoi (argv [2]);
    int message_count = atoi (argv [3]);

    zmq::context_t ctx (1, 1);

    zmq::socket_t s (ctx, ZMQ_PUB);

    //  Add your socket options here.
    //  For example ZMQ_RATE, ZMQ_RECOVERY_IVL and ZMQ_MCAST_LOOP for PGM.

    s.connect (connect_to);

    for (int i = 0; i != message_count; i++) {
        zmq::message_t msg (message_size);
        s.send (msg);
    }

    zmq_sleep (10);

    return 0;
}
