/*
    Copyright (c) 2007-2016 Contributors as noted in the AUTHORS file

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

SETUP_TEARDOWN_TESTCONTEXT

void test_roundtrip ()
{
    void *sb = test_context_socket (ZMQ_REP);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (sb, "ws://*:5556"));

    void *sc = test_context_socket (ZMQ_REQ);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc, "ws://127.0.0.1:5556"));

    bounce (sb, sc);

    test_context_socket_close (sc);
    test_context_socket_close (sb);
}

void test_short_message ()
{
    void *sb = test_context_socket (ZMQ_REP);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (sb, "ws://*:5557"));

    void *sc = test_context_socket (ZMQ_REQ);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc, "ws://127.0.0.1:5557"));

    zmq_msg_t msg;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init_size (&msg, 255));

    for (unsigned char i = 0; i < 255; ++i)
        ((unsigned char *) zmq_msg_data (&msg))[i] = i;

    int rc = zmq_msg_send (&msg, sc, 0);
    TEST_ASSERT_EQUAL_INT (255, rc);

    rc = zmq_msg_recv (&msg, sb, 0);
    TEST_ASSERT_EQUAL_INT (255, rc);

    for (unsigned char i = 0; i < 255; ++i)
        TEST_ASSERT_EQUAL_INT (i, ((unsigned char *) zmq_msg_data (&msg))[i]);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg));

    test_context_socket_close (sc);
    test_context_socket_close (sb);
}

void test_large_message ()
{
    void *sb = test_context_socket (ZMQ_REP);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (sb, "ws://*:5557"));

    void *sc = test_context_socket (ZMQ_REQ);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc, "ws://127.0.0.1:5557"));

    zmq_msg_t msg;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init_size (&msg, 65536));

    for (int i = 0; i < 65536; ++i)
        ((unsigned char *) zmq_msg_data (&msg))[i] = i % 255;

    int rc = zmq_msg_send (&msg, sc, 0);
    TEST_ASSERT_EQUAL_INT (65536, rc);

    rc = zmq_msg_recv (&msg, sb, 0);
    TEST_ASSERT_EQUAL_INT (65536, rc);

    for (int i = 0; i < 65536; ++i)
        TEST_ASSERT_EQUAL_INT (i % 255,
                               ((unsigned char *) zmq_msg_data (&msg))[i]);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg));

    test_context_socket_close (sc);
    test_context_socket_close (sb);
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_roundtrip);
    RUN_TEST (test_short_message);
    RUN_TEST (test_large_message);
    return UNITY_END ();
}
