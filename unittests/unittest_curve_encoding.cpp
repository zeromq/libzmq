/*
Copyright (c) 2018 Contributors as noted in the AUTHORS file

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

#include "../tests/testutil_unity.hpp"

// TODO: remove this ugly hack
#ifdef close
#undef close
#endif

#include <curve_mechanism_base.hpp>
#include <msg.hpp>
#include <random.hpp>

#include <unity.h>

#include <vector>

void setUp ()
{
}

void tearDown ()
{
}

void test_roundtrip (zmq::msg_t *msg_)
{
#ifdef ZMQ_HAVE_CURVE
    const std::vector<uint8_t> original (static_cast<uint8_t *> (msg_->data ()),
                                         static_cast<uint8_t *> (msg_->data ())
                                           + msg_->size ());

    zmq::curve_encoding_t encoding_client ("CurveZMQMESSAGEC",
                                           "CurveZMQMESSAGES",
                                           false);
    zmq::curve_encoding_t encoding_server ("CurveZMQMESSAGES",
                                           "CurveZMQMESSAGEC",
                                           false);

    uint8_t client_public[32];
    uint8_t client_secret[32];
    TEST_ASSERT_SUCCESS_ERRNO (
      crypto_box_keypair (client_public, client_secret));

    uint8_t server_public[32];
    uint8_t server_secret[32];
    TEST_ASSERT_SUCCESS_ERRNO (
      crypto_box_keypair (server_public, server_secret));

    TEST_ASSERT_SUCCESS_ERRNO (
      crypto_box_beforenm (encoding_client.get_writable_precom_buffer (),
                           server_public, client_secret));
    TEST_ASSERT_SUCCESS_ERRNO (
      crypto_box_beforenm (encoding_server.get_writable_precom_buffer (),
                           client_public, server_secret));

    TEST_ASSERT_SUCCESS_ERRNO (encoding_client.encode (msg_));

    // TODO: This is hacky...
    encoding_server.set_peer_nonce (0);
    int error_event_code;
    TEST_ASSERT_SUCCESS_ERRNO (
      encoding_server.decode (msg_, &error_event_code));

    TEST_ASSERT_EQUAL_INT (original.size (), msg_->size ());
    if (!original.empty ()) {
        TEST_ASSERT_EQUAL_UINT8_ARRAY (&original[0], msg_->data (),
                                       original.size ());
    }
#else
    TEST_IGNORE_MESSAGE ("CURVE support is disabled");
#endif
}

void test_roundtrip_empty ()
{
    zmq::msg_t msg;
    msg.init ();

    test_roundtrip (&msg);

    msg.close ();
}

void test_roundtrip_small ()
{
    zmq::msg_t msg;
    msg.init_size (32);
    memcpy (msg.data (), "0123456789ABCDEF0123456789ABCDEF", 32);

    test_roundtrip (&msg);

    msg.close ();
}

void test_roundtrip_large ()
{
    zmq::msg_t msg;
    msg.init_size (2048);
    for (size_t pos = 0; pos < 2048; pos += 32) {
        memcpy (static_cast<char *> (msg.data ()) + pos,
                "0123456789ABCDEF0123456789ABCDEF", 32);
    }

    test_roundtrip (&msg);

    msg.close ();
}

void test_roundtrip_empty_more ()
{
    zmq::msg_t msg;
    msg.init ();
    msg.set_flags (zmq::msg_t::more);

    test_roundtrip (&msg);
    TEST_ASSERT_TRUE (msg.flags () & zmq::msg_t::more);

    msg.close ();
}

int main ()
{
    setup_test_environment ();
    zmq::random_open ();

    UNITY_BEGIN ();

    RUN_TEST (test_roundtrip_empty);
    RUN_TEST (test_roundtrip_small);
    RUN_TEST (test_roundtrip_large);

    RUN_TEST (test_roundtrip_empty_more);

    zmq::random_close ();

    return UNITY_END ();
}
