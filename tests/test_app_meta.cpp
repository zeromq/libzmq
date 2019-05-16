/*
    Copyright (c) 2007-2018 Contributors as noted in the AUTHORS file

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
#include <unity.h>

#include <string.h>

void setUp ()
{
}
void tearDown ()
{
}

void test_app_meta_reqrep ()
{
    void *ctx;
    zmq_msg_t msg;
    void *rep_sock, *req_sock;
    char connect_address[MAX_SOCKET_STRING];
    const char *req_hello = "X-hello:hello";
    const char *req_connection = "X-connection:primary";
    const char *req_z85 = "X-bin:009c6";
    const char *rep_hello = "X-hello:world";
    const char *rep_connection = "X-connection:backup";
    const char *bad_strings[] = {
      ":",
      "key:",
      ":value",
      "keyvalue",
      "",
      "X-"
      "KeyTooLongKeyTooLongKeyTooLongKeyTooLongKeyTooLongKeyTooLongKeyTooLongKe"
      "yTooLongKeyTooLongKeyTooLongKeyTooLongKeyTooLongKeyTooLongKeyTooLongKeyT"
      "ooLongKeyTooLongKeyTooLongKeyTooLongKeyTooLongKeyTooLongKeyTooLongKeyToo"
      "LongKeyTooLongKeyTooLongKeyTooLongKeyTooLong:value"};

    ctx = zmq_ctx_new ();
    rep_sock = zmq_socket (ctx, ZMQ_REP);
    TEST_ASSERT_NOT_NULL (rep_sock);
    req_sock = zmq_socket (ctx, ZMQ_REQ);
    TEST_ASSERT_NOT_NULL (req_sock);

    int rc =
      zmq_setsockopt (rep_sock, ZMQ_METADATA, rep_hello, strlen (rep_hello));
    TEST_ASSERT_EQUAL_INT (0, rc);

    int l = 0;
    rc = zmq_setsockopt (rep_sock, ZMQ_LINGER, &l, sizeof (l));
    TEST_ASSERT_EQUAL_INT (0, rc);

    rc = zmq_setsockopt (rep_sock, ZMQ_METADATA, rep_connection,
                         strlen (rep_connection));
    TEST_ASSERT_EQUAL_INT (0, rc);

    for (int i = 0; i < 6; i++) {
        rc = zmq_setsockopt (rep_sock, ZMQ_METADATA, bad_strings[i],
                             strlen (bad_strings[i]));
        TEST_ASSERT_EQUAL_INT (-1, rc);
    }

    bind_loopback_ipv4 (rep_sock, connect_address, sizeof connect_address);

    l = 0;
    rc = zmq_setsockopt (req_sock, ZMQ_LINGER, &l, sizeof (l));
    TEST_ASSERT_EQUAL_INT (0, rc);

    rc = zmq_setsockopt (req_sock, ZMQ_METADATA, req_hello, strlen (req_hello));
    TEST_ASSERT_EQUAL_INT (0, rc);

    rc = zmq_setsockopt (req_sock, ZMQ_METADATA, req_connection,
                         strlen (req_connection));
    TEST_ASSERT_EQUAL_INT (0, rc);

    rc = zmq_setsockopt (req_sock, ZMQ_METADATA, req_z85, strlen (req_z85));
    TEST_ASSERT_EQUAL_INT (0, rc);

    rc = zmq_connect (req_sock, connect_address);
    TEST_ASSERT_EQUAL_INT (0, rc);

    rc = zmq_msg_init_size (&msg, 1);
    TEST_ASSERT_EQUAL_INT (0, rc);

    char *data = (char *) zmq_msg_data (&msg);
    data[0] = 1;

    rc = zmq_msg_send (&msg, req_sock, 0);
    TEST_ASSERT_EQUAL_INT (1, rc);

    rc = zmq_msg_init (&msg);
    TEST_ASSERT_EQUAL_INT (0, rc);

    rc = zmq_msg_recv (&msg, rep_sock, 0);
    TEST_ASSERT_EQUAL_INT (1, rc);

    TEST_ASSERT_EQUAL_STRING ("hello", zmq_msg_gets (&msg, "X-hello"));
    TEST_ASSERT_EQUAL_STRING ("primary", zmq_msg_gets (&msg, "X-connection"));
    char *bindata = (char *) zmq_msg_gets (&msg, "X-bin");
    TEST_ASSERT_NOT_NULL (bindata);
    uint8_t rawdata[4];
    void *ret = zmq_z85_decode (rawdata, bindata);
    TEST_ASSERT_NOT_NULL (ret);
    TEST_ASSERT_EQUAL_UINT8 (0, rawdata[0]);
    TEST_ASSERT_EQUAL_UINT8 (1, rawdata[1]);
    TEST_ASSERT_EQUAL_UINT8 (2, rawdata[2]);
    TEST_ASSERT_EQUAL_UINT8 (3, rawdata[3]);

    TEST_ASSERT_NULL (zmq_msg_gets (&msg, "X-foobar"));
    TEST_ASSERT_NULL (zmq_msg_gets (&msg, "foobar"));

    rc = zmq_msg_send (&msg, rep_sock, 0);
    TEST_ASSERT_EQUAL_INT (1, rc);

    rc = zmq_msg_recv (&msg, req_sock, 0);
    TEST_ASSERT_EQUAL_INT (1, rc);

    TEST_ASSERT_EQUAL_STRING ("world", zmq_msg_gets (&msg, "X-hello"));
    TEST_ASSERT_EQUAL_STRING ("backup", zmq_msg_gets (&msg, "X-connection"));

    rc = zmq_msg_close (&msg);
    TEST_ASSERT_EQUAL_INT (0, rc);

    rc = zmq_close (req_sock);
    TEST_ASSERT_EQUAL_INT (0, rc);

    rc = zmq_close (rep_sock);
    TEST_ASSERT_EQUAL_INT (0, rc);

    zmq_ctx_term (ctx);
}


int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_app_meta_reqrep);

    return UNITY_END ();
}
