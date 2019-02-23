/*
    Copyright (c) 2007-2017 Contributors as noted in the AUTHORS file

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
#if defined(ZMQ_HAVE_WINDOWS)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdexcept>
#define close closesocket
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

static void zap_handler (void *handler_)
{
    //  Process ZAP requests forever
    while (true) {
        char *version = s_recv (handler_);
        if (!version)
            break; //  Terminating

        char *sequence = s_recv (handler_);
        char *domain = s_recv (handler_);
        char *address = s_recv (handler_);
        char *routing_id = s_recv (handler_);
        char *mechanism = s_recv (handler_);

        assert (streq (version, "1.0"));
        assert (streq (mechanism, "NULL"));

        s_sendmore (handler_, version);
        s_sendmore (handler_, sequence);
        if (streq (domain, "TEST")) {
            s_sendmore (handler_, "200");
            s_sendmore (handler_, "OK");
            s_sendmore (handler_, "anonymous");
            s_send (handler_, "");
        } else {
            s_sendmore (handler_, "400");
            s_sendmore (handler_, "BAD DOMAIN");
            s_sendmore (handler_, "");
            s_send (handler_, "");
        }
        free (version);
        free (sequence);
        free (domain);
        free (address);
        free (routing_id);
        free (mechanism);
    }
    close_zero_linger (handler_);
}

int main (void)
{
    setup_test_environment ();
    size_t len = MAX_SOCKET_STRING;
    char my_endpoint[MAX_SOCKET_STRING];
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    //  We first test client/server with a ZAP domain but with no handler
    //  If there is no handler, libzmq should ignore the ZAP option unless
    //  ZMQ_ZAP_ENFORCE_DOMAIN is set
    void *server = zmq_socket (ctx, ZMQ_DEALER);
    assert (server);
    void *client = zmq_socket (ctx, ZMQ_DEALER);
    assert (client);
    int rc = zmq_setsockopt (server, ZMQ_ZAP_DOMAIN, "TEST", 5);
    assert (rc == 0);
    rc = zmq_bind (server, "tcp://127.0.0.1:*");
    assert (rc == 0);
    rc = zmq_getsockopt (server, ZMQ_LAST_ENDPOINT, my_endpoint, &len);
    assert (rc == 0);
    rc = zmq_connect (client, my_endpoint);
    assert (rc == 0);
    bounce (server, client);
    close_zero_linger (client);
    close_zero_linger (server);

#ifdef ZMQ_ZAP_ENFORCE_DOMAIN
    //  Now set ZMQ_ZAP_ENFORCE_DOMAIN which strictly enforces the ZAP
    //  RFC but is backward-incompatible, now it should fail
    server = zmq_socket (ctx, ZMQ_DEALER);
    assert (server);
    client = zmq_socket (ctx, ZMQ_DEALER);
    assert (client);
    int required = 1;
    rc =
      zmq_setsockopt (server, ZMQ_ZAP_ENFORCE_DOMAIN, &required, sizeof (int));
    assert (rc == 0);
    rc = zmq_setsockopt (server, ZMQ_ZAP_DOMAIN, "TEST", 5);
    assert (rc == 0);
    rc = zmq_bind (server, "tcp://127.0.0.1:*");
    assert (rc == 0);
    rc = zmq_getsockopt (server, ZMQ_LAST_ENDPOINT, my_endpoint, &len);
    assert (rc == 0);
    rc = zmq_connect (client, my_endpoint);
    assert (rc == 0);
    expect_bounce_fail (server, client);
    close_zero_linger (client);
    close_zero_linger (server);
#endif

    //  Spawn ZAP handler
    //  We create and bind ZAP socket in main thread to avoid case
    //  where child thread does not start up fast enough.
    void *handler = zmq_socket (ctx, ZMQ_REP);
    assert (handler);
    rc = zmq_bind (handler, "inproc://zeromq.zap.01");
    assert (rc == 0);
    void *zap_thread = zmq_threadstart (&zap_handler, handler);

    //  We bounce between a binding server and a connecting client

    //  We first test client/server with no ZAP domain
    //  Libzmq does not call our ZAP handler, the connect must succeed
    server = zmq_socket (ctx, ZMQ_DEALER);
    assert (server);
    client = zmq_socket (ctx, ZMQ_DEALER);
    assert (client);
    rc = zmq_bind (server, "tcp://127.0.0.1:*");
    assert (rc == 0);
    rc = zmq_getsockopt (server, ZMQ_LAST_ENDPOINT, my_endpoint, &len);
    assert (rc == 0);
    rc = zmq_connect (client, my_endpoint);
    assert (rc == 0);
    bounce (server, client);
    close_zero_linger (client);
    close_zero_linger (server);

    //  Now define a ZAP domain for the server; this enables
    //  authentication. We're using the wrong domain so this test
    //  must fail.
    server = zmq_socket (ctx, ZMQ_DEALER);
    assert (server);
    client = zmq_socket (ctx, ZMQ_DEALER);
    assert (client);
    rc = zmq_setsockopt (server, ZMQ_ZAP_DOMAIN, "WRONG", 5);
    assert (rc == 0);
    rc = zmq_bind (server, "tcp://127.0.0.1:*");
    assert (rc == 0);
    len = MAX_SOCKET_STRING;
    rc = zmq_getsockopt (server, ZMQ_LAST_ENDPOINT, my_endpoint, &len);
    assert (rc == 0);
    rc = zmq_connect (client, my_endpoint);
    assert (rc == 0);
    expect_bounce_fail (server, client);
    close_zero_linger (client);
    close_zero_linger (server);

    //  Now use the right domain, the test must pass
    server = zmq_socket (ctx, ZMQ_DEALER);
    assert (server);
    client = zmq_socket (ctx, ZMQ_DEALER);
    assert (client);
    rc = zmq_setsockopt (server, ZMQ_ZAP_DOMAIN, "TEST", 4);
    assert (rc == 0);
    rc = zmq_bind (server, "tcp://127.0.0.1:*");
    assert (rc == 0);
    len = MAX_SOCKET_STRING;
    rc = zmq_getsockopt (server, ZMQ_LAST_ENDPOINT, my_endpoint, &len);
    assert (rc == 0);
    rc = zmq_connect (client, my_endpoint);
    assert (rc == 0);
    bounce (server, client);
    close_zero_linger (client);
    close_zero_linger (server);

    // Unauthenticated messages from a vanilla socket shouldn't be received
    server = zmq_socket (ctx, ZMQ_DEALER);
    assert (server);
    rc = zmq_setsockopt (server, ZMQ_ZAP_DOMAIN, "WRONG", 5);
    assert (rc == 0);
    rc = zmq_bind (server, "tcp://127.0.0.1:*");
    assert (rc == 0);

    len = MAX_SOCKET_STRING;
    rc = zmq_getsockopt (server, ZMQ_LAST_ENDPOINT, my_endpoint, &len);
    assert (rc == 0);

    struct sockaddr_in ip4addr;
    fd_t s;

    unsigned short int port;
    rc = sscanf (my_endpoint, "tcp://127.0.0.1:%hu", &port);
    assert (rc == 1);

    ip4addr.sin_family = AF_INET;
    ip4addr.sin_port = htons (port);
#if defined(ZMQ_HAVE_WINDOWS) && (_WIN32_WINNT < 0x0600)
    ip4addr.sin_addr.s_addr = inet_addr ("127.0.0.1");
#else
    inet_pton (AF_INET, "127.0.0.1", &ip4addr.sin_addr);
#endif

    s = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
    rc = connect (s, (struct sockaddr *) &ip4addr, sizeof ip4addr);
    assert (rc > -1);
    // send anonymous ZMTP/1.0 greeting
    send (s, "\x01\x00", 2, 0);
    // send sneaky message that shouldn't be received
    send (s, "\x08\x00sneaky\0", 9, 0);
    int timeout = 250;
    zmq_setsockopt (server, ZMQ_RCVTIMEO, &timeout, sizeof (timeout));
    char *buf = s_recv (server);
    if (buf != NULL) {
        printf ("Received unauthenticated message: %s\n", buf);
        assert (buf == NULL);
    }
    close (s);
    close_zero_linger (server);

    //  Shutdown
    rc = zmq_ctx_term (ctx);
    assert (rc == 0);
    //  Wait until ZAP handler terminates
    zmq_threadclose (zap_thread);

    return 0;
}
