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

#include <string.h>
#include "testutil.hpp"
#include "testutil_unity.hpp"

SETUP_TEARDOWN_TESTCONTEXT

#ifdef ZMQ_WSS_CERT_PEM
const char *key =
  "-----BEGIN PRIVATE KEY-----\n"
  "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\n"
  "lMwbKi/uEdrUT3ei3nAxnuQolXgClZk=\n"
  "-----END PRIVATE KEY-----";

const char *cert =
  "-----BEGIN CERTIFICATE-----\n"
  "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\n"
  "-----END CERTIFICATE-----";

void test_roundtrip ()
{
    char connect_address[MAX_SOCKET_STRING + strlen ("/roundtrip")];
    size_t addr_length = sizeof (connect_address);
    void *sb = test_context_socket (ZMQ_REP);
    zmq_setsockopt (sb, ZMQ_WSS_CERT_PEM, cert, strlen (cert));
    zmq_setsockopt (sb, ZMQ_WSS_KEY_PEM, key, strlen (key));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (sb, "wss://*:*/roundtrip"));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (sb, ZMQ_LAST_ENDPOINT, connect_address, &addr_length));
    strcat (connect_address, "/roundtrip");

    void *sc = test_context_socket (ZMQ_REQ);
    zmq_setsockopt (sc, ZMQ_WSS_TRUST_PEM, cert, strlen (cert));
    zmq_setsockopt (sc, ZMQ_WSS_HOSTNAME, "zeromq.org", strlen ("zeromq.org"));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc, connect_address));

    bounce (sb, sc);

    test_context_socket_close (sc);
    test_context_socket_close (sb);
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_roundtrip);
    return UNITY_END ();
}
#else
int main ()
{
    printf ("WSS unavailable, skipping test\n");
    return 77;
}
#endif
