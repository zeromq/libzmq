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
#include "testutil_unity.hpp"

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

#include <stdlib.h>

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

        TEST_ASSERT_EQUAL_STRING ("1.0", version);
        TEST_ASSERT_EQUAL_STRING ("NULL", mechanism);

        send_string_expect_success (handler_, version, ZMQ_SNDMORE);
        send_string_expect_success (handler_, sequence, ZMQ_SNDMORE);
        if (streq (domain, "TEST")) {
            send_string_expect_success (handler_, "200", ZMQ_SNDMORE);
            send_string_expect_success (handler_, "OK", ZMQ_SNDMORE);
            send_string_expect_success (handler_, "anonymous", ZMQ_SNDMORE);
            send_string_expect_success (handler_, "", 0);
        } else {
            send_string_expect_success (handler_, "400", ZMQ_SNDMORE);
            send_string_expect_success (handler_, "BAD DOMAIN", ZMQ_SNDMORE);
            send_string_expect_success (handler_, "", ZMQ_SNDMORE);
            send_string_expect_success (handler_, "", 0);
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

void *zap_thread;

static void setup_zap_handler ()
{
    //  Spawn ZAP handler
    //  We create and bind ZAP socket in main thread to avoid case
    //  where child thread does not start up fast enough.
    void *handler = zmq_socket (get_test_context (), ZMQ_REP);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (handler, "inproc://zeromq.zap.01"));
    zap_thread = zmq_threadstart (&zap_handler, handler);
}

static void teardown_zap_handler ()
{
    //  Wait until ZAP handler terminates
    zmq_threadclose (zap_thread);
}

void setUp ()
{
    setup_test_context ();
    setup_zap_handler ();
}

void tearDown ()
{
    teardown_test_context ();
    teardown_zap_handler ();
}

void test_no_domain ()
{
    //  We first test client/server with no ZAP domain
    //  Libzmq does not call our ZAP handler, the connect must succeed
    void *server = test_context_socket (ZMQ_DEALER);
    void *client = test_context_socket (ZMQ_DEALER);
    char my_endpoint[MAX_SOCKET_STRING];
    bind_loopback_ipv4 (server, my_endpoint, sizeof my_endpoint);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (client, my_endpoint));
    bounce (server, client);
    test_context_socket_close_zero_linger (client);
    test_context_socket_close_zero_linger (server);
}

void test_wrong_domain_fails ()
{
    //  Now define a ZAP domain for the server; this enables
    //  authentication. We're using the wrong domain so this test
    //  must fail.
    void *server = test_context_socket (ZMQ_DEALER);
    void *client = test_context_socket (ZMQ_DEALER);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (server, ZMQ_ZAP_DOMAIN, "WRONG", 5));
    char my_endpoint[MAX_SOCKET_STRING];
    bind_loopback_ipv4 (server, my_endpoint, sizeof my_endpoint);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (client, my_endpoint));
    expect_bounce_fail (server, client);
    test_context_socket_close_zero_linger (client);
    test_context_socket_close_zero_linger (server);
}

void test_success ()
{
    //  Now use the right domain, the test must pass
    void *server = test_context_socket (ZMQ_DEALER);
    void *client = test_context_socket (ZMQ_DEALER);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (server, ZMQ_ZAP_DOMAIN, "TEST", 4));
    char my_endpoint[MAX_SOCKET_STRING];
    bind_loopback_ipv4 (server, my_endpoint, sizeof my_endpoint);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (client, my_endpoint));
    bounce (server, client);
    test_context_socket_close_zero_linger (client);
    test_context_socket_close_zero_linger (server);
}

void test_vanilla_socket ()
{
    // Unauthenticated messages from a vanilla socket shouldn't be received
    void *server = test_context_socket (ZMQ_DEALER);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (server, ZMQ_ZAP_DOMAIN, "WRONG", 5));
    char my_endpoint[MAX_SOCKET_STRING];
    bind_loopback_ipv4 (server, my_endpoint, sizeof my_endpoint);

    struct sockaddr_in ip4addr;
    fd_t s;

    unsigned short int port;
    int rc = sscanf (my_endpoint, "tcp://127.0.0.1:%hu", &port);
    TEST_ASSERT_EQUAL_INT (1, rc);

    ip4addr.sin_family = AF_INET;
    ip4addr.sin_port = htons (port);
#if defined(ZMQ_HAVE_WINDOWS) && (_WIN32_WINNT < 0x0600)
    ip4addr.sin_addr.s_addr = inet_addr ("127.0.0.1");
#else
    inet_pton (AF_INET, "127.0.0.1", &ip4addr.sin_addr);
#endif

    s = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
    rc = connect (s, (struct sockaddr *) &ip4addr, sizeof ip4addr);
    TEST_ASSERT_GREATER_THAN_INT (-1, rc);
    // send anonymous ZMTP/1.0 greeting
    send (s, "\x01\x00", 2, 0);
    // send sneaky message that shouldn't be received
    send (s, "\x08\x00sneaky\0", 9, 0);
    int timeout = 250;
    zmq_setsockopt (server, ZMQ_RCVTIMEO, &timeout, sizeof (timeout));
    char *buf = s_recv (server);
    if (buf != NULL) {
        printf ("Received unauthenticated message: %s\n", buf);
        TEST_ASSERT_NULL (buf);
    }
    close (s);
    test_context_socket_close_zero_linger (server);
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_no_domain);
    RUN_TEST (test_wrong_domain_fails);
    RUN_TEST (test_success);
    RUN_TEST (test_vanilla_socket);
    return UNITY_END ();
}
