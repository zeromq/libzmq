/*
    Copyright (c) 2007-2011 iMatix Corporation
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

#include "testutil.hpp"
#include "../include/zmq_utils.h"

#include <pthread.h>

const char *transport_fe = "tcp://127.0.0.1:5560" ;
const char *transport_be = "tcp://127.0.0.1:5561" ;

static void copy_msg(void* from, void* to)
{
    zmq_msg_t msg;

    int more = 1;
    int rc;

    while (more)
    {
        more = 0;
        
        rc = zmq_msg_init(&msg);
        assert (rc == 0);
        rc = zmq_recvmsg(from, &msg, 0);
        assert (rc >= 0);                        
        size_t size = sizeof more;
        rc = zmq_getsockopt(from, ZMQ_RCVMORE, &more, &size);
        assert (rc == 0);

        int flags = (more ? ZMQ_SNDMORE : 0);
        rc = zmq_sendmsg(to, &msg, flags);
        assert (rc >= 0);
        rc = zmq_msg_close(&msg);
        assert (rc == 0);
    }
}

extern "C"
{
    static void *queue (void *ctx)
    {
        int rc;

        void* be = zmq_socket(ctx, ZMQ_XREQ);
        assert (be);
        rc = zmq_bind(be, transport_be);
        assert (rc == 0);

        void* fe = zmq_socket(ctx, ZMQ_XREP);
        assert (fe);
        rc = zmq_bind(fe, transport_fe);
        assert (rc == 0);
        
        zmq_pollitem_t items[2];

        items[0].socket = be;
        items[0].events = ZMQ_POLLIN;
        items[1].socket = fe;
        items[1].events = ZMQ_POLLIN;

        while (true)
        {
            items[0].revents = 0;
            items[1].revents = 0;
            int rc = zmq_poll(items, 2, 5000);
            if (rc < 0)
            {
                break;
            }
            if (rc > 0)
            {
                if (items[0].revents == ZMQ_POLLIN)
                {
                    copy_msg(items[0].socket, items[1].socket);
                }
                if (items[1].revents == ZMQ_POLLIN)
                {
                    copy_msg (items[1].socket, items[0].socket);
                }
            }
        }

        zmq_close(fe);
        zmq_close(be);

        return NULL;
    }
}

int main (int argc, char *argv [])
{

    void *ctx = zmq_init (1);
    assert (ctx);

    pthread_t thread;
    
    int rc = pthread_create (&thread, NULL, queue, ctx);
    assert (rc == 0);

    void *sb = zmq_socket (ctx, ZMQ_REP);
    assert (sb);
    rc = zmq_connect (sb, transport_be);
    assert (rc == 0);

    void *sc = zmq_socket (ctx, ZMQ_REQ);
    assert (sc);
    rc = zmq_connect (sc, transport_fe);
    assert (rc == 0);
    
    bounce (sb, sc);
    
    void *sb2 = zmq_socket (ctx, ZMQ_REP);
    assert (sb2);
    rc = zmq_connect (sb2, transport_be);
    assert (rc == 0);
    
    void *sc2 = zmq_socket (ctx, ZMQ_REQ);
    assert (sc2);
    rc = zmq_connect (sc2, transport_fe);
    assert (rc == 0);

    zmq_sleep(1);

    const char *content = "12345678ABCDEFGH12345678abcdefgh";
    const char *content2 = "12345678NOPQRSTU12345678nopqrstu";

    rc = zmq_send (sc, content, 32, 0);
    assert (rc == 32);
    
    rc = zmq_send (sc2, content2, 32, 0);
    assert (rc == 32);
    
    char buf [32];
    rc = zmq_recv (sb, buf, 32, 0);
    assert (rc == 32);

    char buf2 [32];
    rc = zmq_recv (sb2, buf2, 32, 0);
    assert (rc == 32);

    rc = zmq_send (sb2, buf2, 32, 0);
    assert (rc == 32);

    rc = zmq_send (sb, buf, 32, 0);
    assert (rc == 32);

    char reply [32];
    rc = zmq_recv (sc, reply, 32, 0);
    assert (rc == 32);
    assert (memcmp (reply, content, 32) == 0);

    char reply2 [32];
    rc = zmq_recv (sc2, reply2, 32, 0);
    assert (rc == 32);
    assert (memcmp (reply2, content2, 32) == 0);    

    rc = zmq_close (sc);
    assert (rc == 0);

    rc = zmq_close (sb);
    assert (rc == 0);

    rc = zmq_close (sc2);
    assert (rc == 0);

    rc = zmq_close (sb2);
    assert (rc == 0);

    rc = zmq_term (ctx);
    assert (rc == 0);

    return 0 ;
}
