/*
    Copyright (c) 2007-2016 Contributors as noted in the AUTHORS file

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
    setup_test_environment ();
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    void *server = zmq_socket (ctx, ZMQ_SERVER);
    void *client = zmq_socket (ctx, ZMQ_CLIENT);

    int rc = zmq_bind (server, "inproc://test-client-server");
    assert (rc == 0);

    rc = zmq_connect (client, "inproc://test-client-server");
    assert (rc == 0);

    zmq_msg_t msg;
    rc = zmq_msg_init_size (&msg, 1);
    assert (rc == 0);

    char *data = (char *) zmq_msg_data (&msg);
    data [0] = 1;

    rc = zmq_msg_send (&msg, client, ZMQ_SNDMORE);
    assert (rc == -1);

    rc = zmq_msg_send (&msg, client, 0);
    assert (rc == 1);

    rc = zmq_msg_init (&msg);
    assert (rc == 0);

    rc = zmq_msg_recv (&msg, server, 0);
    assert (rc == 1);

    uint32_t routing_id = zmq_msg_routing_id (&msg);
    assert (routing_id != 0);

    rc = zmq_msg_close (&msg);
    assert (rc == 0);

    rc = zmq_msg_init_size (&msg, 1);
    assert (rc == 0);

    data = (char *)zmq_msg_data (&msg);
    data[0] = 2;

    rc = zmq_msg_set_routing_id (&msg, routing_id);
    assert (rc == 0);

    rc = zmq_msg_send (&msg, server, ZMQ_SNDMORE);
    assert (rc == -1);

    rc = zmq_msg_send (&msg, server, 0);
    assert (rc == 1);

    rc = zmq_msg_recv (&msg, client, 0);
    assert (rc == 1);

    routing_id = zmq_msg_routing_id (&msg);
    assert (routing_id == 0);

    rc = zmq_msg_close (&msg);
    assert (rc == 0);

    rc = zmq_close (server);
    assert (rc == 0);

    rc = zmq_close (client);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    return 0 ;
}
