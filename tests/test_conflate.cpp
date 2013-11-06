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

int main (int argc, char *argv [])
{
    const char *bind_to = "tcp://127.0.0.1:5555";

    int rc;

    void* ctx = zmq_init (1);
    assert (ctx);

    void* s_in = zmq_socket (ctx, ZMQ_PULL);
    assert (s_in);

    int conflate = 1;
    rc = zmq_setsockopt (s_in, ZMQ_CONFLATE, &conflate, sizeof(conflate));
    assert (rc == 0);

    rc = zmq_bind (s_in, bind_to);
    assert (rc == 0);

    void* s_out = zmq_socket (ctx, ZMQ_PUSH);
    assert (s_out);

    rc = zmq_connect (s_out, bind_to);
    assert (rc == 0);

    int message_count = 20;
    for (int j = 0; j < message_count; ++j) {
        rc = zmq_send(s_out, (void*)&j, sizeof(int), 0);
        if (rc < 0) {
            printf ("error in zmq_sendmsg: %s\n", zmq_strerror (errno));
            return -1;
        }
    }
    msleep (SETTLE_TIME);

    int payload_recved = 0;
    rc = zmq_recv (s_in, (void*)&payload_recved, sizeof(int), 0);
    assert (rc > 0);
    assert (payload_recved == message_count - 1);

    rc = zmq_close (s_in);
    assert (rc == 0);

    rc = zmq_close (s_out);
    assert (rc == 0);

    rc = zmq_term (ctx);
    assert (rc == 0);

    return 0;
}
