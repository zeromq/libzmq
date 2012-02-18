/*
    Copyright (c) 2007-2012 iMatix Corporation
    Copyright (c) 2011 250bpm s.r.o.
    Copyright (c) 2007-2011 Other contributors as noted in the AUTHORS file

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

#include <assert.h>
#include <string.h>

#include "../include/zmq.h"

int main (int argc, char *argv [])
{
    //  Create the infrastructure
    void *ctx = zmq_init (1);
    assert (ctx);

    void *sb = zmq_socket (ctx, ZMQ_XREP);
    assert (sb);
    int rc = zmq_bind (sb, "tcp://127.0.0.1:12345");
    assert (rc == 0);

    char test [255];
    size_t siz = 255;
    rc = zmq_getsockopt (sb, ZMQ_LAST_ENDPOINT, test, &siz);
    assert (rc == 0 && strcmp (test, "tcp://127.0.0.1:12345") == 0);

    rc = zmq_bind (sb, "tcp://127.0.0.1:54321");
    assert (rc == 0);

    siz = 255;
    rc = zmq_getsockopt (sb, ZMQ_LAST_ENDPOINT, test, &siz);
    assert (rc == 0 && strcmp (test, "tcp://127.0.0.1:54321") == 0);

    return 0 ;
}

