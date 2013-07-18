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

#include "platform.hpp"
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include "testutil.hpp"

static void *
zap_handler (void *zap)
{
    char *version = s_recv (zap);
    char *sequence = s_recv (zap);
    char *domain = s_recv (zap);
    char *address = s_recv (zap);
    char *mechanism = s_recv (zap);
    char *client_key = s_recv (zap);
    
    assert (streq (version, "1.0"));
    assert (streq (mechanism, "CURVE"));

    s_sendmore (zap, version);
    s_sendmore (zap, sequence);
    s_sendmore (zap, "200");
    s_sendmore (zap, "OK");
    s_sendmore (zap, "anonymous");
    s_send (zap, "");
    
    free (version);
    free (sequence);
    free (domain);
    free (address);
    free (mechanism);
    free (client_key);
    
    int rc = zmq_close (zap);
    assert (rc == 0);

    return NULL;
}

int main (void)
{
#ifndef HAVE_LIBSODIUM
    printf ("libsodium not installed, skipping CURVE test\n");
    return 0;
#endif
    int rc;
    size_t optsize;
    int mechanism;
    int as_server;
    
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    //  Server socket will accept connections
    void *server = zmq_socket (ctx, ZMQ_DEALER);
    assert (server);

    //  Client socket that will try to connect to server
    void *client = zmq_socket (ctx, ZMQ_DEALER);
    assert (client);

    //  Test keys from the zmq_curve man page
    char client_public [] = "Yne@$w-vo<fVvi]a<NY6T1ed:M$fCG*[IaLV{hID";
    char client_secret [] = "D:)Q[IlAW!ahhC2ac:9*A}h:p?([4%wOTJ%JR%cs";
    char server_public [] = "rq:rM>}U?@Lns47E1%kR.o@n%FcmmsL/@{H8]yf7";
    char server_secret [] = "JTKVSB%%)wK0E.X)V>+}o?pNmC{O&4W4b!Ni{Lh6";
        
    as_server = 1;
    rc = zmq_setsockopt (server, ZMQ_CURVE_SERVER, &as_server, sizeof (int));
    assert (rc == 0);
    rc = zmq_setsockopt (server, ZMQ_CURVE_SECRETKEY, server_secret, 40);
    assert (rc == 0);

    rc = zmq_setsockopt (client, ZMQ_CURVE_SERVERKEY, server_public, 40);
    assert (rc == 0);
    rc = zmq_setsockopt (client, ZMQ_CURVE_PUBLICKEY, client_public, 40);
    assert (rc == 0);
    rc = zmq_setsockopt (client, ZMQ_CURVE_SECRETKEY, client_secret, 40);
    assert (rc == 0);

    // Test the client and server both have the right mechanism.
    optsize = sizeof (int);
    rc = zmq_getsockopt (client, ZMQ_MECHANISM, &mechanism, &optsize);
    assert (rc == 0);
    assert (mechanism == ZMQ_CURVE);      
    rc = zmq_getsockopt (server, ZMQ_MECHANISM, &mechanism, &optsize);
    assert (rc == 0);
    assert (mechanism == ZMQ_CURVE);

    // Test the server bit on both client and server.
    rc = zmq_getsockopt (client, ZMQ_CURVE_SERVER, &as_server, &optsize);
    assert (rc == 0);
    assert (as_server == 0);    
    rc = zmq_getsockopt (server, ZMQ_CURVE_SERVER, &as_server, &optsize);
    assert (rc == 0);
    assert (as_server == 1);

    //  Create and bind ZAP socket
    void *zap = zmq_socket (ctx, ZMQ_REP);
    assert (zap);

    rc = zmq_bind (zap, "inproc://zeromq.zap.01");
    assert (rc == 0);

    //  Spawn ZAP handler
    pthread_t zap_thread;
    rc = pthread_create (&zap_thread, NULL, &zap_handler, zap);
    assert (rc == 0);

    rc = zmq_bind (server, "tcp://*:9998");
    assert (rc == 0);
    rc = zmq_connect (client, "tcp://localhost:9998");
    assert (rc == 0);

    bounce (server, client);
    
    rc = zmq_close (client);
    assert (rc == 0);
    rc = zmq_close (server);
    assert (rc == 0);

    //  Wait until ZAP handler terminates.
    pthread_join (zap_thread, NULL);
    
    //  Shutdown
    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    return 0;
}
