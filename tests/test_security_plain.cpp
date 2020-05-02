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

#include <stdlib.h>
#include <string.h>

static void zap_handler (void *zap_)
{
    //  Process ZAP requests forever
    while (true) {
        char *version = s_recv (zap_);
        if (!version)
            break; //  Terminating
        char *sequence = s_recv (zap_);
        char *domain = s_recv (zap_);
        char *address = s_recv (zap_);
        char *routing_id = s_recv (zap_);
        char *mechanism = s_recv (zap_);
        char *username = s_recv (zap_);
        char *password = s_recv (zap_);

        TEST_ASSERT_EQUAL_STRING ("1.0", version);
        TEST_ASSERT_EQUAL_STRING ("PLAIN", mechanism);
        TEST_ASSERT_EQUAL_STRING ("IDENT", routing_id);

        send_string_expect_success (zap_, version, ZMQ_SNDMORE);
        send_string_expect_success (zap_, sequence, ZMQ_SNDMORE);
        if (streq (username, "admin") && streq (password, "password")) {
            send_string_expect_success (zap_, "200", ZMQ_SNDMORE);
            send_string_expect_success (zap_, "OK", ZMQ_SNDMORE);
            send_string_expect_success (zap_, "anonymous", ZMQ_SNDMORE);
            send_string_expect_success (zap_, "", 0);
        } else {
            send_string_expect_success (zap_, "400", ZMQ_SNDMORE);
            send_string_expect_success (zap_, "Invalid username or password",
                                        ZMQ_SNDMORE);
            send_string_expect_success (zap_, "", ZMQ_SNDMORE);
            send_string_expect_success (zap_, "", 0);
        }
        free (version);
        free (sequence);
        free (domain);
        free (address);
        free (routing_id);
        free (mechanism);
        free (username);
        free (password);
    }
    TEST_ASSERT_SUCCESS_ERRNO (zmq_close (zap_));
}

void *zap_thread;

char my_endpoint[MAX_SOCKET_STRING];

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

const char domain[] = "test";

void *server;

static void setup_server ()
{
    //  Server socket will accept connections
    server = test_context_socket (ZMQ_DEALER);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (server, ZMQ_ROUTING_ID, "IDENT", 6));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (server, ZMQ_ZAP_DOMAIN, domain, strlen (domain)));
    const int as_server = 1;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (server, ZMQ_PLAIN_SERVER, &as_server, sizeof (int)));
    bind_loopback_ipv4 (server, my_endpoint, sizeof my_endpoint);
}

static void teardown_server ()
{
    test_context_socket_close (server);
}

void setUp ()
{
    setup_test_context ();
    setup_zap_handler ();
    setup_server ();
}

void tearDown ()
{
    teardown_server ();
    teardown_test_context ();
    teardown_zap_handler ();
}

void test_plain_success ()
{
    //  Check PLAIN security with correct username/password
    void *client = test_context_socket (ZMQ_DEALER);
    const char username[] = "admin";
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (client, ZMQ_PLAIN_USERNAME, username, strlen (username)));
    const char password[] = "password";
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (client, ZMQ_PLAIN_PASSWORD, password, strlen (password)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (client, my_endpoint));
    bounce (server, client);
    test_context_socket_close (client);
}

void test_plain_client_as_server_fails ()
{
    //  Check PLAIN security with badly configured client (as_server)
    //  This will be caught by the plain_server class, not passed to ZAP
    void *client = test_context_socket (ZMQ_DEALER);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (client, ZMQ_ZAP_DOMAIN, domain, strlen (domain)));
    const int as_server = 1;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (client, ZMQ_PLAIN_SERVER, &as_server, sizeof (int)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (client, my_endpoint));
    expect_bounce_fail (server, client);
    test_context_socket_close_zero_linger (client);
}

void test_plain_wrong_credentials_fails ()
{
    //  Check PLAIN security -- failed authentication
    void *client = test_context_socket (ZMQ_DEALER);
    const char username[] = "wronguser";
    const char password[] = "wrongpass";
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (client, ZMQ_PLAIN_USERNAME, username, strlen (username)));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (client, ZMQ_PLAIN_PASSWORD, password, strlen (password)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (client, my_endpoint));
    expect_bounce_fail (server, client);
    test_context_socket_close_zero_linger (client);
}

void test_plain_vanilla_socket ()
{
    // Unauthenticated messages from a vanilla socket shouldn't be received
    fd_t s = connect_socket (my_endpoint);
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
}

int main (void)
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_plain_success);
    RUN_TEST (test_plain_client_as_server_fails);
    RUN_TEST (test_plain_wrong_credentials_fails);
    RUN_TEST (test_plain_vanilla_socket);
    return UNITY_END ();
}
