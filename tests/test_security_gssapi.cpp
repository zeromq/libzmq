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

//  This test requires a KRB5 environment with the following
//  service principal (substitute your host.domain and REALM):
//
//    zmqtest2/host.domain@REALM   (host.domain should be host running test)
//
//  Export keys for this principal to a keytab file and set the environment
//  variables KRB5_KTNAME and KRB5_CLIENT_KTNAME to FILE:/path/to/your/keytab.
//  The test will use it both for client and server roles.
//
//  The test is derived in large part from test_security_curve.cpp

const char *name = "zmqtest2";

static volatile int zap_deny_all = 0;

//  Read one event off the monitor socket; return value and address
//  by reference, if not null, and event number by value. Returns -1
//  in case of error.

static int
get_monitor_event (void *monitor, int *value, char **address)
{
    //  First frame in message contains event number and value
    zmq_msg_t msg;
    zmq_msg_init (&msg);
    if (zmq_msg_recv (&msg, monitor, 0) == -1)
        return -1;              //  Interruped, presumably
    assert (zmq_msg_more (&msg));

    uint8_t *data = (uint8_t *) zmq_msg_data (&msg);
    uint16_t event = *(uint16_t *) (data);
    if (value)
        *value = *(uint32_t *) (data + 2);

    //  Second frame in message contains event address
    zmq_msg_init (&msg);
    if (zmq_msg_recv (&msg, monitor, 0) == -1)
        return -1;              //  Interruped, presumably
    assert (!zmq_msg_more (&msg));

    if (address) {
        uint8_t *data = (uint8_t *) zmq_msg_data (&msg);
        size_t size = zmq_msg_size (&msg);
        *address = (char *) malloc (size + 1);
        memcpy (*address, data, size);
        *address [size] = 0;
    }
    return event;
}

//  --------------------------------------------------------------------------
//  This methods receives and validates ZAP requestes (allowing or denying
//  each client connection).
//  N.B. on failure, each crypto type in keytab will be tried

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
        char *principal = s_recv (handler);

        assert (streq (version, "1.0"));
        assert (streq (mechanism, "GSSAPI"));

        s_sendmore (handler, version);
        s_sendmore (handler, sequence);

        if (!zap_deny_all) {
            s_sendmore (handler, "200");
            s_sendmore (handler, "OK");
            s_sendmore (handler, "anonymous");
            s_send     (handler, "");
	    //fprintf (stderr, "ALLOW %s\n", principal);
        }
        else {
            s_sendmore (handler, "400");
            s_sendmore (handler, "Denied");
            s_sendmore (handler, "");
            s_send     (handler, "");
	    //fprintf (stderr, "DENY %s\n", principal);
        }
        free (version);
        free (sequence);
        free (domain);
        free (address);
        free (identity);
        free (mechanism);
        free (principal);
    }
    zmq_close (handler);
}

void test_valid_creds (void *ctx, void *server, void *server_mon, char *endpoint)
{
    void *client = zmq_socket (ctx, ZMQ_DEALER);
    assert (client);
    int rc = zmq_setsockopt (client, ZMQ_GSSAPI_SERVICE_PRINCIPAL,
                             name, strlen (name) + 1);
    assert (rc == 0);
    rc = zmq_setsockopt (client, ZMQ_GSSAPI_PRINCIPAL,
                         name, strlen (name) + 1);
    assert (rc == 0);
    int name_type = ZMQ_GSSAPI_NT_HOSTBASED;
    rc = zmq_setsockopt (client, ZMQ_GSSAPI_PRINCIPAL_NAMETYPE,
                         &name_type, sizeof (name_type));
    assert (rc == 0);
    rc = zmq_connect (client, endpoint);
    assert (rc == 0);

    bounce (server, client);
    rc = zmq_close (client);
    assert (rc == 0);

    int event = get_monitor_event (server_mon, NULL, NULL);
    assert (event == ZMQ_EVENT_HANDSHAKE_SUCCEED);
}

//  Check security with valid but unauthorized credentials
//  Note: ZAP may see multiple requests - after a failure, client will
//  fall back to other crypto types for principal, if available.
void test_unauth_creds (void *ctx, void *server, void *server_mon, char *endpoint)
{
    void *client = zmq_socket (ctx, ZMQ_DEALER);
    assert (client);
    int rc = zmq_setsockopt (client, ZMQ_GSSAPI_SERVICE_PRINCIPAL,
                              name, strlen (name) + 1);
    assert (rc == 0);
    rc = zmq_setsockopt (client, ZMQ_GSSAPI_PRINCIPAL,
                         name, strlen (name) + 1);
    assert (rc == 0);
    int name_type = ZMQ_GSSAPI_NT_HOSTBASED;
    rc = zmq_setsockopt (client, ZMQ_GSSAPI_PRINCIPAL_NAMETYPE,
                         &name_type, sizeof (name_type));
    assert (rc == 0);
    zap_deny_all = 1;
    rc = zmq_connect (client, endpoint);
    assert (rc == 0);

    expect_bounce_fail (server, client);
    close_zero_linger (client);

    int event = get_monitor_event (server_mon, NULL, NULL);
    assert (event == ZMQ_EVENT_HANDSHAKE_FAILED);
}

//  Check GSSAPI security with NULL client credentials
//  This must be caught by the gssapi_server class, not passed to ZAP
void test_null_creds (void *ctx, void *server, void *server_mon, char *endpoint)
{
    void *client = zmq_socket (ctx, ZMQ_DEALER);
    assert (client);
    int rc = zmq_connect (client, endpoint);
    assert (rc == 0);
    expect_bounce_fail (server, client);
    close_zero_linger (client);

    int event = get_monitor_event (server_mon, NULL, NULL);
    assert (event == ZMQ_EVENT_HANDSHAKE_FAILED);
}

//  Check GSSAPI security with PLAIN client credentials
//  This must be caught by the curve_server class, not passed to ZAP
void test_plain_creds (void *ctx, void *server, void *server_mon, char *endpoint)
{
    void *client = zmq_socket (ctx, ZMQ_DEALER);
    assert (client);
    int rc = zmq_setsockopt (client, ZMQ_PLAIN_USERNAME, "admin", 5);
    assert (rc == 0);
    rc = zmq_setsockopt (client, ZMQ_PLAIN_PASSWORD, "password", 8);
    assert (rc == 0);
    rc = zmq_connect (client, endpoint);
    assert (rc == 0);
    expect_bounce_fail (server, client);
    close_zero_linger (client);
}

// Unauthenticated messages from a vanilla socket shouldn't be received
void test_vanilla_socket (void *ctx, void *server, void *server_mon, char *endpoint)
{
    struct sockaddr_in ip4addr;
    int s;
    unsigned short int port;
    int rc = sscanf(endpoint, "tcp://127.0.0.1:%hu", &port);
    assert (rc == 1);
    ip4addr.sin_family = AF_INET;
    ip4addr.sin_port = htons (port);
#if defined (ZMQ_HAVE_WINDOWS) && (_WIN32_WINNT < 0x0600)
    ip4addr.sin_addr.s_addr = inet_addr ("127.0.0.1");
#else
    inet_pton(AF_INET, "127.0.0.1", &ip4addr.sin_addr);
#endif

    s = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
    int rc = connect (s, (struct sockaddr*) &ip4addr, sizeof (ip4addr));
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
}

int main (void)
{
    if (!getenv ("KRB5_KTNAME") || !getenv ("KRB5_CLIENT_KTNAME")) {
        printf ("KRB5 environment unavailable, skipping test\n");
        return 77; // SKIP
    }
    // Avoid entanglements with user's credential cache
    setenv ("KRB5CCNAME", "MEMORY", 1);

    setup_test_environment ();
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    size_t len = MAX_SOCKET_STRING;
    char my_endpoint[MAX_SOCKET_STRING];

    //  Spawn ZAP handler
    //  We create and bind ZAP socket in main thread to avoid case
    //  where child thread does not start up fast enough.
    void *handler = zmq_socket (ctx, ZMQ_REP);
    assert (handler);
    int rc = zmq_bind (handler, "inproc://zeromq.zap.01");
    assert (rc == 0);
    void *zap_thread = zmq_threadstart (&zap_handler, handler);

    //  Server socket will accept connections
    void *server = zmq_socket (ctx, ZMQ_DEALER);
    assert (server);
    int as_server = 1;
    rc = zmq_setsockopt (server, ZMQ_GSSAPI_SERVER, &as_server, sizeof (int));
    assert (rc == 0);
    rc = zmq_setsockopt (server, ZMQ_GSSAPI_PRINCIPAL,
                         name, strlen (name) + 1);
    assert (rc == 0);
    int name_type = ZMQ_GSSAPI_NT_HOSTBASED;
    rc = zmq_setsockopt (server, ZMQ_GSSAPI_PRINCIPAL_NAMETYPE,
                         &name_type, sizeof (name_type));
    assert (rc == 0);
    rc = zmq_bind (server, "tcp://127.0.0.1:*");
    assert (rc == 0);
    rc = zmq_getsockopt (server, ZMQ_LAST_ENDPOINT, my_endpoint, &len);
    assert (rc == 0);

    //  Monitor handshake events on the server
    rc = zmq_socket_monitor (server, "inproc://monitor-server",
            ZMQ_EVENT_HANDSHAKE_SUCCEED | ZMQ_EVENT_HANDSHAKE_FAILED);
    assert (rc == 0);

    //  Create socket for collecting monitor events
    void *server_mon = zmq_socket (ctx, ZMQ_PAIR);
    assert (server_mon);

    //  Connect it to the inproc endpoints so they'll get events
    rc = zmq_connect (server_mon, "inproc://monitor-server");
    assert (rc == 0);

    //  Attempt various connections
    test_valid_creds (ctx, server, server_mon, my_endpoint);
    test_null_creds (ctx, server, server_mon, my_endpoint);
    test_plain_creds (ctx, server, server_mon, my_endpoint);
    test_vanilla_socket (ctx, server, server_mon, my_endpoint);
    test_unauth_creds (ctx, server, server_mon, my_endpoint);

    //  Shutdown
    close_zero_linger (server_mon);
    rc = zmq_close (server);
    assert (rc == 0);
    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    //  Wait until ZAP handler terminates
    zmq_threadclose (zap_thread);

    return 0;
}
