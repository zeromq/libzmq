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

static void
zap_handler (void *handler)
{
    //  Process ZAP requests forever
    while (true) {
        char *version = s_recv (handler);
        if (!version)
            break;          //  Terminating
        char *sequence = s_recv (handler);
        char *domain = s_recv (handler);
        char *address = s_recv (handler);
        char *identity = s_recv (handler);
        char *mechanism = s_recv (handler);

        assert (streq (version, "1.0"));
        assert (streq (mechanism, "NULL"));
        
        s_sendmore (handler, version);
        s_sendmore (handler, sequence);
        if (streq (domain, "TEST")) {
            s_sendmore (handler, "200");
            s_sendmore (handler, "OK");
            s_sendmore (handler, "anonymous");
            s_send     (handler, "");
        }
        else {
            s_sendmore (handler, "400");
            s_sendmore (handler, "BAD DOMAIN");
            s_sendmore (handler, "");
            s_send     (handler, "");
        }
        free (version);
        free (sequence);
        free (domain);
        free (address);
        free (identity);
        free (mechanism);
    }
    zmq_close (handler);
}

int main (void)
{
    setup_test_environment();
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    //  Spawn ZAP handler
    //  We create and bind ZAP socket in main thread to avoid case
    //  where child thread does not start up fast enough.
    void *handler = zmq_socket (ctx, ZMQ_REP);
    assert (handler);
    int rc = zmq_bind (handler, "inproc://zeromq.zap.01");
    assert (rc == 0);
    void *zap_thread = zmq_threadstart (&zap_handler, handler);

    //  We bounce between a binding server and a connecting client
    void *server = zmq_socket (ctx, ZMQ_DEALER);
    assert (server);
    void *client = zmq_socket (ctx, ZMQ_DEALER);
    assert (client);
    
    //  We first test client/server with no ZAP domain
    //  Libzmq does not call our ZAP handler, the connect must succeed
    rc = zmq_bind (server, "tcp://127.0.0.1:9000");
    assert (rc == 0);
    rc = zmq_connect (client, "tcp://localhost:9000");
    assert (rc == 0);
    bounce (server, client);
    zmq_unbind (server, "tcp://127.0.0.1:9000");
    zmq_disconnect (client, "tcp://localhost:9000");
    
    //  Now define a ZAP domain for the server; this enables 
    //  authentication. We're using the wrong domain so this test
    //  must fail.
    //  **************************************************************
    //  PH: the following causes libzmq to get confused, so that the
    //  next step fails. To reproduce, uncomment this block. Note that
    //  even creating a new client/server socket pair, the behaviour
    //  does not change.
    //  **************************************************************
    //  Destroying the old sockets and creating new ones isn't needed,
    //  but it shows that the problem isn't related to specific sockets.
    //close_zero_linger (client);
    //close_zero_linger (server);
    //server = zmq_socket (ctx, ZMQ_DEALER);
    //assert (server);
    //client = zmq_socket (ctx, ZMQ_DEALER);
    //assert (client);
    ////  The above code should not be required
    //rc = zmq_setsockopt (server, ZMQ_ZAP_DOMAIN, "WRONG", 5);
    //assert (rc == 0);
    //rc = zmq_bind (server, "tcp://127.0.0.1:9001");
    //assert (rc == 0);
    //rc = zmq_connect (client, "tcp://localhost:9001");
    //assert (rc == 0);
    //expect_bounce_fail (server, client);
    //zmq_unbind (server, "tcp://127.0.0.1:9001");
    //zmq_disconnect (client, "tcp://localhost:9001");
    
    //  Now use the right domain, the test must pass
    rc = zmq_setsockopt (server, ZMQ_ZAP_DOMAIN, "TEST", 4);
    assert (rc == 0);
    rc = zmq_bind (server, "tcp://127.0.0.1:9002");
    assert (rc == 0);
    rc = zmq_connect (client, "tcp://localhost:9002");
    assert (rc == 0);
    //  **************************************************************
    //  PH: it fails here; though the ZAP reply is 200 OK, and
    //  null_mechanism.cpp correctly parses that, the connection
    //  never succeeds and the test hangs.
    //  **************************************************************
    bounce (server, client);
    zmq_unbind (server, "tcp://127.0.0.1:9002");
    zmq_disconnect (client, "tcp://localhost:9002");
    
    //  Shutdown
    close_zero_linger (client);
    close_zero_linger (server);
    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    //  Wait until ZAP handler terminates.
    zmq_threadclose (zap_thread);

    return 0;
}
