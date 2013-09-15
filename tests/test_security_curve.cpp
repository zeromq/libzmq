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

#include <string.h>
#include <stdlib.h>
#include "testutil.hpp"
#include "../include/zmq_utils.h"
#include "platform.hpp"

//  Test keys from the zmq_curve man page
static char client_public [] = "Yne@$w-vo<fVvi]a<NY6T1ed:M$fCG*[IaLV{hID";
static char client_secret [] = "D:)Q[IlAW!ahhC2ac:9*A}h:p?([4%wOTJ%JR%cs";
static char server_public [] = "rq:rM>}U?@Lns47E1%kR.o@n%FcmmsL/@{H8]yf7";
static char server_secret [] = "JTKVSB%%)wK0E.X)V>+}o?pNmC{O&4W4b!Ni{Lh6";

//  --------------------------------------------------------------------------
//  Encode a binary frame as a string; destination string MUST be at least
//  size * 5 / 4 bytes long plus 1 byte for the null terminator. Returns
//  dest. Size must be a multiple of 4.

//  Maps base 256 to base 85
static char encoder [85 + 1] = {
    "0123456789" "abcdefghij" "klmnopqrst" "uvwxyzABCD"
    "EFGHIJKLMN" "OPQRSTUVWX" "YZ.-:+=^!/" "*?&<>()[]{" 
    "}@%$#"
};

static char *
Z85_encode (char *dest, uint8_t *data, size_t size)
{
    assert (size % 4 == 0);
    unsigned int char_nbr = 0;
    unsigned int byte_nbr = 0;
    uint32_t value = 0;
    while (byte_nbr < size) {
        //  Accumulate value in base 256 (binary)
        value = value * 256 + data [byte_nbr++];
        if (byte_nbr % 4 == 0) {
            //  Output value in base 85
            unsigned int divisor = 85 * 85 * 85 * 85;
            while (divisor) {
                dest [char_nbr++] = encoder [value / divisor % 85];
                divisor /= 85;
            }
            value = 0;
        }
    }
    assert (char_nbr == size * 5 / 4);
    dest [char_nbr] = 0;
    return dest;
}


static void zap_handler (void *ctx)
{
    //  Create and bind ZAP socket
    void *zap = zmq_socket (ctx, ZMQ_REP);
    assert (zap);
    int rc = zmq_bind (zap, "inproc://zeromq.zap.01");
    assert (rc == 0);

    //  Process ZAP requests forever
    while (true) {
        char *version = s_recv (zap);
        if (!version)
            break;          //  Terminating

        char *sequence = s_recv (zap);
        char *domain = s_recv (zap);
        char *address = s_recv (zap);
        char *identity = s_recv (zap);
        char *mechanism = s_recv (zap);
        uint8_t client_key [32];
        int size = zmq_recv (zap, client_key, 32, 0);
        assert (size == 32);

        char client_key_text [41];
        Z85_encode (client_key_text, client_key, 32);

        assert (streq (version, "1.0"));
        assert (streq (mechanism, "CURVE"));
        assert (streq (identity, "IDENT"));

        s_sendmore (zap, version);
        s_sendmore (zap, sequence);

        if (streq (client_key_text, client_public)) {
            s_sendmore (zap, "200");
            s_sendmore (zap, "OK");
            s_sendmore (zap, "anonymous");
            s_send (zap, "");
        }
        else {
            s_sendmore (zap, "400");
            s_sendmore (zap, "Invalid client public key");
            s_sendmore (zap, "");
            s_send (zap, "");
        }
        free (version);
        free (sequence);
        free (domain);
        free (address);
        free (identity);
        free (mechanism);
    }
    rc = zmq_close (zap);
    assert (rc == 0);
}


int main (void)
{
#ifndef HAVE_LIBSODIUM
    printf ("libsodium not installed, skipping CURVE test\n");
    return 0;
#endif
    setup_test_environment ();
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    //  Spawn ZAP handler
    void *zap_thread = zmq_threadstart (&zap_handler, ctx);

    //  Server socket will accept connections
    void *server = zmq_socket (ctx, ZMQ_DEALER);
    assert (server);
    int as_server = 1;
    int rc = zmq_setsockopt (server, ZMQ_CURVE_SERVER, &as_server, sizeof (int));
    assert (rc == 0);
    rc = zmq_setsockopt (server, ZMQ_CURVE_SECRETKEY, server_secret, 40);
    assert (rc == 0);
    rc = zmq_setsockopt (server, ZMQ_IDENTITY, "IDENT", 6);
    assert (rc == 0);
    rc = zmq_bind (server, "tcp://*:9998");
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
    rc = zmq_connect (client, "tcp://localhost:9998");
    assert (rc == 0);
    bounce (server, client);
    rc = zmq_close (client);
    assert (rc == 0);

    //  Check CURVE security with a garbage server key
    //  This will be caught by the curve_server class, not passed to ZAP
    char garbage_key [] = "0000111122223333444455556666777788889999";
    client = zmq_socket (ctx, ZMQ_DEALER);
    assert (client);
    rc = zmq_setsockopt (client, ZMQ_CURVE_SERVERKEY, garbage_key, 40);
    assert (rc == 0);
    rc = zmq_setsockopt (client, ZMQ_CURVE_PUBLICKEY, client_public, 40);
    assert (rc == 0);
    rc = zmq_setsockopt (client, ZMQ_CURVE_SECRETKEY, client_secret, 40);
    assert (rc == 0);
    rc = zmq_connect (client, "tcp://localhost:9998");
    assert (rc == 0);
    expect_bounce_fail (server, client);
    close_zero_linger (client);

    //  Check CURVE security with a garbage client public key
    //  This will be caught by the curve_server class, not passed to ZAP
    client = zmq_socket (ctx, ZMQ_DEALER);
    assert (client);
    rc = zmq_setsockopt (client, ZMQ_CURVE_SERVERKEY, server_public, 40);
    assert (rc == 0);
    rc = zmq_setsockopt (client, ZMQ_CURVE_PUBLICKEY, garbage_key, 40);
    assert (rc == 0);
    rc = zmq_setsockopt (client, ZMQ_CURVE_SECRETKEY, client_secret, 40);
    assert (rc == 0);
    rc = zmq_connect (client, "tcp://localhost:9998");
    assert (rc == 0);
    expect_bounce_fail (server, client);
    close_zero_linger (client);

    //  Check CURVE security with a garbage client secret key
    //  This will be caught by the curve_server class, not passed to ZAP
    client = zmq_socket (ctx, ZMQ_DEALER);
    assert (client);
    rc = zmq_setsockopt (client, ZMQ_CURVE_SERVERKEY, server_public, 40);
    assert (rc == 0);
    rc = zmq_setsockopt (client, ZMQ_CURVE_PUBLICKEY, client_public, 40);
    assert (rc == 0);
    rc = zmq_setsockopt (client, ZMQ_CURVE_SECRETKEY, garbage_key, 40);
    assert (rc == 0);
    rc = zmq_connect (client, "tcp://localhost:9998");
    assert (rc == 0);
    expect_bounce_fail (server, client);
    close_zero_linger (client);

    //  Check CURVE security with bogus client credentials
    //  This must be caught by the ZAP handler
    char bogus_public [] = "8)<]6{NT{}=MZBsH)i%l0k}y*^i#80n-Yf{I8Z+P";
    char bogus_secret [] = "[m9E0TW2Mf?Ke3K>fuBGCrkBpc6aJbj4jv4451Nx";

    client = zmq_socket (ctx, ZMQ_DEALER);
    assert (client);
    rc = zmq_setsockopt (client, ZMQ_CURVE_SERVERKEY, server_public, 40);
    assert (rc == 0);
    rc = zmq_setsockopt (client, ZMQ_CURVE_PUBLICKEY, bogus_public, 40);
    assert (rc == 0);
    rc = zmq_setsockopt (client, ZMQ_CURVE_SECRETKEY, bogus_secret, 40);
    assert (rc == 0);
    rc = zmq_connect (client, "tcp://localhost:9998");
    assert (rc == 0);
    expect_bounce_fail (server, client);
    close_zero_linger (client);

    //  Shutdown
    rc = zmq_close (server);
    assert (rc == 0);
    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    //  Wait until ZAP handler terminates
    zmq_threadclose (zap_thread);

    return 0;
}
