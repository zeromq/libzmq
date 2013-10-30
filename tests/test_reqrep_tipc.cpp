/*
    Copyright (c) 2010-2011 250bpm s.r.o.
    Copyright (c) 2011 iMatix Corporation
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
    fprintf (stderr, "test_reqrep_tipc running...\n");

    void *ctx = zmq_init (1);
    assert (ctx);

    void *sb = zmq_socket (ctx, ZMQ_REP);
    assert (sb);
    int rc = zmq_bind (sb, "tipc://{5560,0,0}");
    assert (rc == 0);

    void *sc = zmq_socket (ctx, ZMQ_REQ);
    assert (sc);
    rc = zmq_connect (sc, "tipc://{5560,0}");
    assert (rc == 0);

    bounce (sb, sc);

    rc = zmq_close (sc);
    assert (rc == 0);

    rc = zmq_close (sb);
    assert (rc == 0);

    rc = zmq_term (ctx);
    assert (rc == 0);

    return 0 ;
}
