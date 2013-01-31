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
#include "../include/zmq_utils.h"

int main (void)
{
    fprintf (stderr, "test_router_mandatory running...\n");

    void *ctx = zmq_ctx_new ();
    assert (ctx);

    // Creating the first socket.
    void *sa = zmq_socket (ctx, ZMQ_ROUTER);
    assert (sa);
    
    int hwm = 1;
    int rc = zmq_setsockopt (sa, ZMQ_SNDHWM, &hwm, sizeof (hwm));
    assert (rc == 0);

    rc = zmq_bind (sa, "tcp://127.0.0.1:15560");
    assert (rc == 0);

    // Sending a message to an unknown peer with the default setting
    rc = zmq_send (sa, "UNKNOWN", 7, ZMQ_SNDMORE);
    assert (rc == 7);
    rc = zmq_send (sa, "DATA", 4, 0);
    assert (rc == 4);

    int mandatory = 1;

    // Set mandatory routing on socket
    rc = zmq_setsockopt (sa, ZMQ_ROUTER_MANDATORY, &mandatory, sizeof (mandatory));
    assert (rc == 0);

    // Send a message and check that it fails
    rc = zmq_send (sa, "UNKNOWN", 7, ZMQ_SNDMORE | ZMQ_DONTWAIT);
    assert (rc == -1 && errno == EHOSTUNREACH);

    // Create a valid socket
    void *sb = zmq_socket (ctx, ZMQ_DEALER);
    assert (sb);

    rc = zmq_setsockopt (sb, ZMQ_RCVHWM, &hwm, sizeof (hwm));
    assert (rc == 0);

    rc = zmq_setsockopt (sb, ZMQ_IDENTITY, "X", 1);
    assert (rc == 0);
    
    rc = zmq_connect (sb, "tcp://127.0.0.1:15560");
    assert (rc == 0);

    // wait until connect
    zmq_sleep (1);

    // make it full and check that it fails
    rc = zmq_send (sa, "X", 1, ZMQ_SNDMORE);
    assert (rc == 1);
    rc = zmq_send (sa, "DATA1", 5, 0);
    assert (rc == 5);

    rc = zmq_send (sa, "X", 1, ZMQ_SNDMORE | ZMQ_DONTWAIT);
    if (rc == 1) {
        // the first frame has been sent
        rc = zmq_send (sa, "DATA2", 5, 0);
        assert (rc == 5);
    
        // send more
        rc = zmq_send (sa, "X", 1, ZMQ_SNDMORE | ZMQ_DONTWAIT);
    } 

    assert (rc == -1 && errno == EAGAIN);


    rc = zmq_close (sa);
    assert (rc == 0);

    rc = zmq_close (sb);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    return 0 ;
}
