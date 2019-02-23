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

#include <unity.h>

void *sb;
void *sc;

void setUp ()
{
    setup_test_context ();

    sb = test_context_socket (ZMQ_PAIR);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (sb, "inproc://a"));

    sc = test_context_socket (ZMQ_PAIR);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc, "inproc://a"));
}

void tearDown ()
{
    test_context_socket_close (sc);
    test_context_socket_close (sb);

    teardown_test_context ();
}

void test_roundtrip ()
{
    bounce (sb, sc);
}

// TODO it appears that this has nothing to do with pair or inproc, and belongs somewhere else
void test_zmq_send_const ()
{
    TEST_ASSERT_EQUAL_INT (3, TEST_ASSERT_SUCCESS_ERRNO (
                                zmq_send_const (sb, "foo", 3, ZMQ_SNDMORE)));
    TEST_ASSERT_EQUAL_INT (
      6, TEST_ASSERT_SUCCESS_ERRNO (zmq_send_const (sb, "foobar", 6, 0)));

    recv_string_expect_success (sc, "foo", 0);
    recv_string_expect_success (sc, "foobar", 0);
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_roundtrip);
    RUN_TEST (test_zmq_send_const);
    return UNITY_END ();
}
