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

#include <stdlib.h>

SETUP_TEARDOWN_TESTCONTEXT

char connect_address[MAX_SOCKET_STRING];

void test_fair_queue_in (const char *bind_address_)
{
    void *rep = test_context_socket (ZMQ_REP);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (rep, bind_address_));
    size_t len = MAX_SOCKET_STRING;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (rep, ZMQ_LAST_ENDPOINT, connect_address, &len));

    const size_t services = 5;
    void *reqs[services];
    for (size_t peer = 0; peer < services; ++peer) {
        reqs[peer] = test_context_socket (ZMQ_REQ);

        TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (reqs[peer], connect_address));
    }

    msleep (SETTLE_TIME);

    s_send_seq (reqs[0], "A", SEQ_END);
    s_recv_seq (rep, "A", SEQ_END);
    s_send_seq (rep, "A", SEQ_END);
    s_recv_seq (reqs[0], "A", SEQ_END);

    s_send_seq (reqs[0], "A", SEQ_END);
    s_recv_seq (rep, "A", SEQ_END);
    s_send_seq (rep, "A", SEQ_END);
    s_recv_seq (reqs[0], "A", SEQ_END);

    // TODO: following test fails randomly on some boxes
#ifdef SOMEONE_FIXES_THIS
    // send N requests
    for (size_t peer = 0; peer < services; ++peer) {
        char *str = strdup ("A");
        str[0] += peer;
        s_send_seq (reqs[peer], str, SEQ_END);
        free (str);
    }

    // handle N requests
    for (size_t peer = 0; peer < services; ++peer) {
        char *str = strdup ("A");
        str[0] += peer;
        //  Test fails here
        s_recv_seq (rep, str, SEQ_END);
        s_send_seq (rep, str, SEQ_END);
        s_recv_seq (reqs[peer], str, SEQ_END);
        free (str);
    }
#endif
    test_context_socket_close_zero_linger (rep);

    for (size_t peer = 0; peer < services; ++peer)
        test_context_socket_close_zero_linger (reqs[peer]);
}

void test_envelope (const char *bind_address_)
{
    void *rep = test_context_socket (ZMQ_REP);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (rep, bind_address_));
    size_t len = MAX_SOCKET_STRING;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (rep, ZMQ_LAST_ENDPOINT, connect_address, &len));

    void *dealer = test_context_socket (ZMQ_DEALER);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (dealer, connect_address));

    // minimal envelope
    s_send_seq (dealer, 0, "A", SEQ_END);
    s_recv_seq (rep, "A", SEQ_END);
    s_send_seq (rep, "A", SEQ_END);
    s_recv_seq (dealer, 0, "A", SEQ_END);

    // big envelope
    s_send_seq (dealer, "X", "Y", 0, "A", SEQ_END);
    s_recv_seq (rep, "A", SEQ_END);
    s_send_seq (rep, "A", SEQ_END);
    s_recv_seq (dealer, "X", "Y", 0, "A", SEQ_END);

    test_context_socket_close_zero_linger (rep);
    test_context_socket_close_zero_linger (dealer);
}

const char bind_inproc[] = "inproc://a";
const char bind_tcp[] = "tcp://127.0.0.1:*";

void test_fair_queue_in_inproc ()
{
    test_fair_queue_in (bind_inproc);
}

void test_fair_queue_in_tcp ()
{
    test_fair_queue_in (bind_tcp);
}

void test_envelope_inproc ()
{
    test_envelope (bind_inproc);
}

void test_envelope_tcp ()
{
    test_envelope (bind_tcp);
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();

    // SHALL receive incoming messages from its peers using a fair-queuing
    // strategy.
    RUN_TEST (test_fair_queue_in_inproc);
    RUN_TEST (test_fair_queue_in_tcp);

    // For an incoming message:
    // SHALL remove and store the address envelope, including the delimiter.
    // SHALL pass the remaining data frames to its calling application.
    // SHALL wait for a single reply message from its calling application.
    // SHALL prepend the address envelope and delimiter.
    // SHALL deliver this message back to the originating peer.
    RUN_TEST (test_envelope_inproc);
    RUN_TEST (test_envelope_tcp);

    return UNITY_END ();
}
