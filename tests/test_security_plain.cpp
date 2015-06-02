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
#if defined (ZMQ_HAVE_WINDOWS)
#   include <winsock2.h>
#   include <ws2tcpip.h>
#   include <stdexcept>
#   define close closesocket
#else
#   include <sys/socket.h>
#   include <netinet/in.h>
#   include <arpa/inet.h>
#   include <unistd.h>
#endif

static void
zap_handler (void *ctx)
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
        char *username = s_recv (zap);
        char *password = s_recv (zap);

        assert (streq (version, "1.0"));
        assert (streq (mechanism, "PLAIN"));
        assert (streq (identity, "IDENT"));

        s_sendmore (zap, version);
        s_sendmore (zap, sequence);
        if (streq (username, "admin")
        &&  streq (password, "password")) {
            s_sendmore (zap, "200");
            s_sendmore (zap, "OK");
            s_sendmore (zap, "anonymous");
            s_send (zap, "");
        }
        else {
            s_sendmore (zap, "400");
            s_sendmore (zap, "Invalid username or password");
            s_sendmore (zap, "");
            s_send (zap, "");
        }
        free (version);
        free (sequence);
        free (domain);
        free (address);
        free (identity);
        free (mechanism);
        free (username);
        free (password);
    }
    rc = zmq_close (zap);
    assert (rc == 0);
}

int main (void)
{
    setup_test_environment();
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    //  Spawn ZAP handler
    void *zap_thread = zmq_threadstart (&zap_handler, ctx);

    //  Server socket will accept connections
    void *server = zmq_socket (ctx, ZMQ_DEALER);
    assert (server);
    int rc = zmq_setsockopt (server, ZMQ_IDENTITY, "IDENT", 6);
    assert (rc == 0);
    int as_server = 1;
    rc = zmq_setsockopt (server, ZMQ_PLAIN_SERVER, &as_server, sizeof (int));
    assert (rc == 0);
    rc = zmq_bind (server, "tcp://127.0.0.1:9998");
    assert (rc == 0);

    char username [256];
    char password [256];

    //  Check PLAIN security with correct username/password
    void *client = zmq_socket (ctx, ZMQ_DEALER);
    assert (client);
    strcpy (username, "admin");
    rc = zmq_setsockopt (client, ZMQ_PLAIN_USERNAME, username, strlen (username));
    assert (rc == 0);
    strcpy (password, "password");
    rc = zmq_setsockopt (client, ZMQ_PLAIN_PASSWORD, password, strlen (password));
    assert (rc == 0);
    rc = zmq_connect (client, "tcp://localhost:9998");
    assert (rc == 0);
    bounce (server, client);
    rc = zmq_close (client);
    assert (rc == 0);

    //  Check PLAIN security with badly configured client (as_server)
    //  This will be caught by the plain_server class, not passed to ZAP
    client = zmq_socket (ctx, ZMQ_DEALER);
    assert (client);
    as_server = 1;
    rc = zmq_setsockopt (client, ZMQ_PLAIN_SERVER, &as_server, sizeof (int));
    assert (rc == 0);
    rc = zmq_connect (client, "tcp://localhost:9998");
    assert (rc == 0);
    expect_bounce_fail (server, client);
    close_zero_linger (client);

    //  Check PLAIN security -- failed authentication
    client = zmq_socket (ctx, ZMQ_DEALER);
    assert (client);
    strcpy (username, "wronguser");
    strcpy (password, "wrongpass");
    rc = zmq_setsockopt (client, ZMQ_PLAIN_USERNAME, username, strlen (username));
    assert (rc == 0);
    rc = zmq_setsockopt (client, ZMQ_PLAIN_PASSWORD, password, strlen (password));
    assert (rc == 0);
    rc = zmq_connect (client, "tcp://localhost:9998");
    assert (rc == 0);
    expect_bounce_fail (server, client);
    close_zero_linger (client);

    // Unauthenticated messages from a vanilla socket shouldn't be received
    struct sockaddr_in ip4addr;
    int s;

    ip4addr.sin_family = AF_INET;
    ip4addr.sin_port = htons (9998);
    inet_pton (AF_INET, "127.0.0.1", &ip4addr.sin_addr);

    s = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
    rc = connect (s, (struct sockaddr*) &ip4addr, sizeof (ip4addr));
    assert (rc > -1);
    // send anonymous ZMTP/1.0 greeting
    send (s, "\x01\x00", 2, 0);
    // send sneaky message that shouldn't be received
    send (s, "\x08\x00sneaky\0", 9, 0);
    int timeout = 150;
    zmq_setsockopt (server, ZMQ_RCVTIMEO, &timeout, sizeof (timeout));
    char *buf = s_recv (server);
    if (buf != NULL) {
        printf ("Received unauthenticated message: %s\n", buf);
        assert (buf == NULL);
    }
    close (s);

    //  Shutdown
    rc = zmq_close (server);
    assert (rc == 0);
    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    //  Wait until ZAP handler terminates
    zmq_threadclose (zap_thread);

    return 0;
}
