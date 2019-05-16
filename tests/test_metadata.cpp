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
#include <unity.h>

void setUp ()
{
}

void tearDown ()
{
}

static void zap_handler (void *handler_)
{
    uint8_t metadata[] = {5, 'H', 'e', 'l', 'l', 'o', 0,  0,
                          0, 5,   'W', 'o', 'r', 'l', 'd'};

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
        if (streq (domain, "DOMAIN")) {
            send_string_expect_success (handler_, "200", ZMQ_SNDMORE);
            send_string_expect_success (handler_, "OK", ZMQ_SNDMORE);
            send_string_expect_success (handler_, "anonymous", ZMQ_SNDMORE);
            zmq_send (handler_, metadata, sizeof (metadata), 0);
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

void test_metadata ()
{
    char my_endpoint[MAX_SOCKET_STRING];
    setup_test_context ();

    //  Spawn ZAP handler
    //  We create and bind ZAP socket in main thread to avoid case
    //  where child thread does not start up fast enough.
    void *handler = zmq_socket (get_test_context (), ZMQ_REP);
    TEST_ASSERT_NOT_NULL (handler);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (handler, "inproc://zeromq.zap.01"));
    void *zap_thread = zmq_threadstart (&zap_handler, handler);

    void *server = test_context_socket (ZMQ_DEALER);
    void *client = test_context_socket (ZMQ_DEALER);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (server, ZMQ_ZAP_DOMAIN, "DOMAIN", 6));
    bind_loopback_ipv4 (server, my_endpoint, sizeof (my_endpoint));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (client, my_endpoint));

    send_string_expect_success (client, "This is a message", 0);
    zmq_msg_t msg;
    zmq_msg_init (&msg);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_recv (&msg, server, 0));
    TEST_ASSERT_EQUAL_STRING ("World", zmq_msg_gets (&msg, "Hello"));
    TEST_ASSERT_EQUAL_STRING ("DEALER", zmq_msg_gets (&msg, "Socket-Type"));
    TEST_ASSERT_EQUAL_STRING ("anonymous", zmq_msg_gets (&msg, "User-Id"));
    TEST_ASSERT_EQUAL_STRING ("127.0.0.1", zmq_msg_gets (&msg, "Peer-Address"));

    TEST_ASSERT_NULL (zmq_msg_gets (&msg, "No Such"));
    TEST_ASSERT_EQUAL_INT (EINVAL, zmq_errno ());
    zmq_msg_close (&msg);

    test_context_socket_close_zero_linger (client);
    test_context_socket_close_zero_linger (server);

    //  Shutdown
    teardown_test_context ();

    //  Wait until ZAP handler terminates
    zmq_threadclose (zap_thread);
}

int main ()
{
    setup_test_environment ();
    UNITY_BEGIN ();
    RUN_TEST (test_metadata);
    return UNITY_END ();
}
