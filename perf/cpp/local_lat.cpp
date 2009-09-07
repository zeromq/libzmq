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
#include <unistd.h>
#include <assert.h>
#include <stddef.h>

int main (int argc, char *argv [])
{
    if (argc != 4) {
        printf ("usage: local_lat <bind-to> <message-size> "
            "<roundtrip-count>\n");
        return 1;
    }
    const char *bind_to = argv [1];
    size_t message_size = (size_t) atoi (argv [2]);
    int roundtrip_count = atoi (argv [3]);

    zmq::context_t ctx (1, 1);

    zmq::socket_t s (ctx, ZMQ_REP);
    s.bind (bind_to);

    for (int i = 0; i != roundtrip_count; i++) {
        zmq::message_t msg;
        s.recv (&msg);
        assert (msg.size () == message_size);
        s.send (msg);
    }

    sleep (1);

    return 0;
}
