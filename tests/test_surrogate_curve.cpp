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

//  We'll generate random test keys at startup
static char client_public [41];
static char client_secret [41];
static char server_public [41];
static char server_secret [41];

//  --------------------------------------------------------------------------
//  Encode a binary frame as a string; destination string MUST be at least
//  size * 5 / 4 bytes long plus 1 byte for the null terminator. Returns
//  dest. Size must be a multiple of 4.

static void zap_handler (void *handler)
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
        uint8_t client_key [32];
        int size = zmq_recv (handler, client_key, 32, 0);
        assert (size == 32);

        char client_key_text [41];
        zmq_z85_encode (client_key_text, client_key, 32);

        assert (streq (version, "1.0"));
        assert (streq (mechanism, "CURVE"));
        assert (streq (identity, "IDENT"));

        s_sendmore (handler, version);
        s_sendmore (handler, sequence);

        if (streq (client_key_text, client_public)) {
            s_sendmore (handler, "200");
            s_sendmore (handler, "OK");
            s_sendmore (handler, "anonymous");
            s_send     (handler, "");
        }
        else {
            s_sendmore (handler, "400");
            s_sendmore (handler, "Invalid client public key");
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

void
nop_proxy (void *ctx)
{
    // Frontend socket talks to clients over TCP
    void *frontend = zmq_socket (ctx, ZMQ_ROUTER);
    assert (frontend);
    int as_server = 1;
    int rc = zmq_setsockopt (frontend, ZMQ_NOP_NODE, &as_server, sizeof (int));
    assert (rc == 0);
    bool surrogate_curve = true;
	rc = zmq_setsockopt (frontend, ZMQ_USE_SURROGATION_MECHANISM, &surrogate_curve, sizeof (bool));
	assert (rc == 0);
	int surrogation_mechanism = ZMQ_NULL;
	rc = zmq_setsockopt (frontend, ZMQ_SURROGATION_MECHANISM, &surrogation_mechanism, sizeof (int));
	assert (rc == 0);
    rc = zmq_bind (frontend, "tcp://127.0.0.1:9999");
    assert (rc == 0);

    // Backend socket talks to workers over inproc
    void *backend = zmq_socket (ctx, ZMQ_DEALER);
    assert (backend);
    rc = zmq_setsockopt (backend, ZMQ_NOP_NODE, &as_server, sizeof (int));
    assert (rc == 0);
	rc = zmq_setsockopt (backend, ZMQ_USE_SURROGATION_MECHANISM, &surrogate_curve, sizeof (bool));
	assert (rc == 0);
	rc = zmq_setsockopt (backend, ZMQ_SURROGATION_MECHANISM, &surrogation_mechanism, sizeof (int));
	assert (rc == 0);
    rc = zmq_bind (backend, "tcp://127.0.0.1:9998");
    assert (rc == 0);

    // Connect backend to frontend via a proxy
    zmq_proxy (frontend, backend, NULL);

    rc = zmq_close (frontend);
    assert (rc == 0);
    rc = zmq_close (backend);
    assert (rc == 0);
}

int main (void)
{
#ifndef HAVE_LIBSODIUM
    printf ("libsodium not installed, skipping CURVE test\n");
    return 0;
#endif

    //  Generate new keypairs for this test
    int rc = zmq_curve_keypair (client_public, client_secret);
    assert (rc == 0);
    rc = zmq_curve_keypair (server_public, server_secret);
    assert (rc == 0);

    setup_test_environment ();
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    //  Spawn ZAP handler
    //  We create and bind ZAP socket in main thread to avoid case
    //  where child thread does not start up fast enough.
    void *handler = zmq_socket (ctx, ZMQ_REP);
    assert (handler);
    rc = zmq_bind (handler, "inproc://zeromq.zap.01");
    assert (rc == 0);
    void *zap_thread = zmq_threadstart (&zap_handler, handler);

    //  Server socket will accept connections
    void *server = zmq_socket (ctx, ZMQ_DEALER);
    assert (server);
    int as_server = 1;
    rc = zmq_setsockopt (server, ZMQ_CURVE_SERVER, &as_server, sizeof (int));
    assert (rc == 0);
    rc = zmq_setsockopt (server, ZMQ_CURVE_SECRETKEY, server_secret, 40);
    assert (rc == 0);
    bool surrogate_curve = true;
    rc = zmq_setsockopt (server, ZMQ_USE_SURROGATION_MECHANISM, &surrogate_curve, sizeof (bool));
    assert (rc == 0);
    int surrogation_mechanism = ZMQ_NULL;
    rc = zmq_setsockopt (server, ZMQ_SURROGATION_MECHANISM, &surrogation_mechanism, sizeof (int));
    assert (rc == 0);
    rc = zmq_setsockopt (server, ZMQ_IDENTITY, "IDENT", 6);
    assert (rc == 0);
    rc = zmq_connect (server, "tcp://127.0.0.1:9998");
    assert (rc == 0);

    //  Check CURVE security with valid credentials
    void *client = zmq_socket (ctx, ZMQ_DEALER);
    assert (client);
    rc = zmq_setsockopt (client, ZMQ_CURVE_SERVERKEY, server_public, 40);
    assert (rc == 0);
    rc = zmq_setsockopt (client, ZMQ_CURVE_PUBLICKEY, client_public, 40);
    assert (rc == 0);
    rc = zmq_setsockopt (client, ZMQ_CURVE_SECRETKEY, client_secret, 40);
    assert (rc == 0);
    rc = zmq_setsockopt (client, ZMQ_USE_SURROGATION_MECHANISM, &surrogate_curve, sizeof (bool));
    assert (rc == 0);
    rc = zmq_setsockopt (client, ZMQ_SURROGATION_MECHANISM, &surrogation_mechanism, sizeof (int));
    assert (rc == 0);
    rc = zmq_connect (client, "tcp://127.0.0.1:9999");
    assert (rc == 0);

    // Launch the NULL proxy in a thread, to connect backend to frontend - as we have one single worker (server here), we don't have to mind the one-to-one client/worker relationship required by CURVE
    void* proxy_thread = zmq_threadstart (&nop_proxy, ctx);

    // Perform some exchanges
    bounce (server, client);


    //  Shutdown
    rc = zmq_close (client);
    assert (rc == 0);
    rc = zmq_close (server);
    assert (rc == 0);
    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    //  Wait until ZAP handler terminates
    zmq_threadclose (zap_thread);
    // Wait until the proxy terminates
    zmq_threadclose (proxy_thread);

    return 0;
}
