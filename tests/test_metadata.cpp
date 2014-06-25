/*
    Copyright (c) 2007-2014 Contributors as noted in the AUTHORS file

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
    uint8_t metadata [] = {
        5, 'H', 'e', 'l', 'l', 'o',
        0, 0, 0, 5, 'W', 'o', 'r', 'l', 'd'
    };

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
        if (streq (domain, "DOMAIN")) {
            s_sendmore (handler, "200");
            s_sendmore (handler, "OK");
            s_sendmore (handler, "anonymous");
            zmq_send (handler, metadata, sizeof (metadata), 0);
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
    close_zero_linger (handler);
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

    void *server = zmq_socket (ctx, ZMQ_DEALER);
    assert (server);
    void *client = zmq_socket (ctx, ZMQ_DEALER);
    assert (client);
    rc = zmq_setsockopt (server, ZMQ_ZAP_DOMAIN, "DOMAIN", 6);
    assert (rc == 0);
    rc = zmq_bind (server, "tcp://127.0.0.1:9001");
    assert (rc == 0);
    rc = zmq_connect (client, "tcp://127.0.0.1:9001");
    assert (rc == 0);

    s_send (client, "This is a message");
    zmq_msg_t msg;
    zmq_msg_init (&msg);
    rc = zmq_msg_recv (&msg, server, 0);
    assert (rc != -1);
    assert (streq (zmq_msg_gets (&msg, "Hello"), "World"));
    assert (streq (zmq_msg_gets (&msg, "Socket-Type"), "DEALER"));
    assert (streq (zmq_msg_gets (&msg, "User-Id"), "anonymous"));
    assert (zmq_msg_gets (&msg, "No Such") == NULL);
    assert (zmq_errno () == EINVAL);
    zmq_msg_close (&msg);

    close_zero_linger (client);
    close_zero_linger (server);

    //  Shutdown
    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    //  Wait until ZAP handler terminates
    zmq_threadclose (zap_thread);

    return 0;
}
