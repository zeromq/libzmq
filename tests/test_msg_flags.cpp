/*
    Copyright (c) 2007-2015 Contributors as noted in the AUTHORS file

    This file is part of libzmq, the ZeroMQ core engine in C++.

    libzmq is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License (LGPL) as published
    by the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    As a special exception, the Contributors give you permission to link
    this library with independent modules to produce an executable,
    regardless of the license terms of these independent modules, and to
    copy and distribute the resulting executable under terms of your choice,
    provided that you also meet, for each linked independent module, the
    terms and conditions of the license of that module. An independent
    module is a module which is not derived from or based on this library.
    If you modify this library, you must extend this exception to your
    version of the library.

    libzmq is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
    FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
    License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "testutil.hpp"

int main (void)
{
    setup_test_environment();
    //  Create the infrastructure
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    void *sb = zmq_socket (ctx, ZMQ_ROUTER);
    assert (sb);

    int rc = zmq_bind (sb, "inproc://a");
    assert (rc == 0);

    void *sc = zmq_socket (ctx, ZMQ_DEALER);
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
    rc = zmq_msg_recv (&msg, sb, 0);
    assert (rc >= 0);
    int more = zmq_msg_more (&msg);
    assert (more == 1);

    //  Then the first part of the message body.
    rc = zmq_msg_recv (&msg, sb, 0);
    assert (rc == 1);
    more = zmq_msg_more (&msg);
    assert (more == 1);

    //  And finally, the second part of the message body.
    rc = zmq_msg_recv (&msg, sb, 0);
    assert (rc == 1);
    more = zmq_msg_more (&msg);
    assert (more == 0);

    // Test ZMQ_SHARED property (case 1, refcounted messages)
    zmq_msg_t msg_a;
    rc = zmq_msg_init_size(&msg_a, 1024); // large enough to be a type_lmsg
    assert (rc == 0);

    // Message is not shared
    rc = zmq_msg_get(&msg_a, ZMQ_SHARED);
    assert (rc == 0);

    zmq_msg_t msg_b;
    rc = zmq_msg_init(&msg_b);
    assert (rc == 0);

    rc = zmq_msg_copy(&msg_b, &msg_a);
    assert (rc == 0);

    // Message is now shared
    rc = zmq_msg_get(&msg_b, ZMQ_SHARED);
    assert (rc == 1);

    // cleanup
    rc = zmq_msg_close(&msg_a);
    assert (rc == 0);
    rc = zmq_msg_close(&msg_b);
    assert (rc == 0);

    // Test ZMQ_SHARED property (case 2, constant data messages)
    rc = zmq_msg_init_data(&msg_a, (void*) "TEST", 5, 0, 0);
    assert (rc == 0);

    // Message reports as shared
    rc = zmq_msg_get(&msg_a, ZMQ_SHARED);
    assert (rc == 1);

    // cleanup
    rc = zmq_msg_close(&msg_a);
    assert (rc == 0);

    //  Deallocate the infrastructure.
    rc = zmq_close (sc);
    assert (rc == 0);

    rc = zmq_close (sb);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);
    return 0 ;
}

