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
    char *mechanism = s_recv (zap);
    char *client_key = s_recv (zap);
    
    assert (streq (version, "1.0"));
    assert (streq (mechanism, "CURVE"));

    s_sendmore (zap, version);
    s_sendmore (zap, sequence);
    s_sendmore (zap, "200");
    s_sendmore (zap, "OK");
    s_send     (zap, "anonymous");
    
    free (version);
    free (sequence);
    free (domain);
    free (mechanism);
    free (client_key);
    
    int rc = zmq_close (zap);
    assert (rc == 0);

    return NULL;
}

int main (void)
{
#ifndef HAVE_LIBSODIUM
    printf("libsodium not installed, skipping CURVE test\n");
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

    as_server = 1;
    rc = zmq_setsockopt(server, ZMQ_CURVE_SERVER, &as_server, sizeof(int));
    // Test key from the zmq_curve man page.
    uint8_t server_secret[32] = {
      0x8E, 0x0B, 0xDD, 0x69, 0x76, 0x28, 0xB9, 0x1D, 0x8F, 0x24,
      0x55, 0x87, 0xEE, 0x95, 0xC5, 0xB0, 0x4D, 0x48, 0x96, 0x3F,
      0x79, 0x25, 0x98, 0x77, 0xB4, 0x9C, 0xD9, 0x06, 0x3A, 0xEA, 
      0xD3, 0xB7  
    };
    rc = zmq_setsockopt(server, ZMQ_CURVE_SECRETKEY, server_secret, sizeof(server_secret));
    assert(rc == 0);

    // Test client keys from the zmq_curve man page.
    uint8_t server_public[32] = {
        0x54, 0xFC, 0xBA, 0x24, 0xE9, 0x32, 0x49, 0x96, 0x93, 0x16,
        0xFB, 0x61, 0x7C, 0x87, 0x2B, 0xB0, 0xC1, 0xD1, 0xFF, 0x14,
        0x80, 0x04, 0x27, 0xC5, 0x94, 0xCB, 0xFA, 0xCF, 0x1B, 0xC2,
        0xD6, 0x52
    };
    rc = zmq_setsockopt(client, ZMQ_CURVE_SERVERKEY, server_public, sizeof(server_public));
    assert(rc == 0);
    uint8_t client_public[32] = {
        0xBB, 0x88, 0x47, 0x1D, 0x65, 0xE2, 0x65, 0x9B, 0x30, 0xC5,
        0x5A, 0x53, 0x21, 0xCE, 0xBB, 0x5A, 0xAB, 0x2B, 0x70, 0xA3,
        0x98, 0x64, 0x5C, 0x26, 0xDC, 0xA2, 0xB2, 0xFC, 0xB4, 0x3F,
        0xC5, 0x18
    };
    rc = zmq_setsockopt(client, ZMQ_CURVE_PUBLICKEY, client_public, sizeof(client_public));
    assert(rc == 0);
    uint8_t client_secret[32] = {
        0x7B, 0xB8, 0x64, 0xB4, 0x89, 0xAF, 0xA3, 0x67, 0x1F, 0xBE,
        0x69, 0x10, 0x1F, 0x94, 0xB3, 0x89, 0x72, 0xF2, 0x48, 0x16,
        0xDF, 0xB0, 0x1B, 0x51, 0x65, 0x6B, 0x3F, 0xEC, 0x8D, 0xFD,
        0x08, 0x88
    };
    rc = zmq_setsockopt(client, ZMQ_CURVE_SECRETKEY, client_secret, sizeof(client_secret));
    assert(rc == 0);

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
