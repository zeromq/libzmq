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

int main (void)
{
    setup_test_environment();
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    //  We bounce between a binding server and a connecting client
    void *server = zmq_socket (ctx, ZMQ_DEALER);
    assert (server);
    int is_server = 1;
    int rc = zmq_setsockopt (server, ZMQ_NOP_NODE, &is_server, sizeof (int));
    assert (rc == 0);
    void *client = zmq_socket (ctx, ZMQ_DEALER);
    assert (client);
    is_server = 0;
    rc = zmq_setsockopt (client, ZMQ_NOP_NODE, &is_server, sizeof (int));
    assert (rc == 0);
    
    //  We first test client/server with no ZAP domain
    //  Libzmq does not call our ZAP handler, the connect must succeed
    rc = zmq_bind (server, "tcp://127.0.0.1:9998");
    assert (rc == 0);
    rc = zmq_connect (client, "tcp://127.0.0.1:9998");
    assert (rc == 0);
    bounce (server, client);
    zmq_unbind (server, "tcp://127.0.0.1:9998");
    zmq_disconnect (client, "tcp://127.0.0.1:9998");
    
    
    //  Shutdown
    close_zero_linger (client);
    close_zero_linger (server);
    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    return 0;
}
