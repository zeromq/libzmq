/*
    Copyright (c) 2011 250bpm s.r.o.

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
    void *ctx = zmq_init (0);
    assert (ctx);
    void *sb = zmq_socket (ctx, ZMQ_XREP);
    assert (sb);
    int rc = zmq_bind (sb, "inproc://a");
    assert (rc == 0);
    void *sc = zmq_socket (ctx, ZMQ_XREQ);
    assert (sc);
    rc = zmq_connect (sc, "inproc://a");
    assert (rc == 0);
   
    //  Send 2-part message.
    rc = zmq_send (sc, "A", 1, ZMQ_SNDMORE);
    assert (rc == 1);
    rc = zmq_send (sc, "B", 1, 0);
    assert (rc == 1);

    //  Identity comes first.
    zmq_msg_t msg;
    rc = zmq_msg_init (&msg);
    assert (rc == 0);
    rc = zmq_recvmsg (sb, &msg, 0);
    assert (rc >= 0);
    int more;
    size_t more_size = sizeof (more);
    rc = zmq_getmsgopt (&msg, ZMQ_MORE, &more, &more_size);
    assert (rc == 0);
    assert (more == 1);

    //  Then the first part of the message body.
    rc = zmq_recvmsg (sb, &msg, 0);
    assert (rc == 1);
    more_size = sizeof (more);
    rc = zmq_getmsgopt (&msg, ZMQ_MORE, &more, &more_size);
    assert (rc == 0);
    assert (more == 1);

    //  And finally, the second part of the message body.
    rc = zmq_recvmsg (sb, &msg, 0);
    assert (rc == 1);
    more_size = sizeof (more);
    rc = zmq_getmsgopt (&msg, ZMQ_MORE, &more, &more_size);
    assert (rc == 0);
    assert (more == 0);

    //  Deallocate the infrastructure.
    rc = zmq_close (sc);
    assert (rc == 0);
    rc = zmq_close (sb);
    assert (rc == 0);
    rc = zmq_term (ctx);
    assert (rc == 0);
    return 0 ;
}

