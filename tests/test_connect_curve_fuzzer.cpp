/*
    Copyright (c) 2020 Contributors as noted in the AUTHORS file

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

#ifdef ZMQ_USE_FUZZING_ENGINE
#include <fuzzer/FuzzedDataProvider.h>
#endif

#include "testutil.hpp"
#include "testutil_security.hpp"

// Test that the ZMTP engine handles invalid handshake when connecting
// https://rfc.zeromq.org/spec/37/
// https://rfc.zeromq.org/spec/26/
extern "C" int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
    const char *fixed_client_public =
      "{{k*81)yMWEF{/BxdMd[5RL^qRFxBgoL<8m.D^KD";
    const char *fixed_client_secret =
      "N?Gmik8R[2ACw{b7*[-$S6[4}aO#?DB?#=<OQPc7";
    const char *fixed_server_public =
      "3.9-xXwy{g*w72TP*3iB9IJJRxlBH<ufTAvPd2>C";

    setup_test_context ();
    char my_endpoint[MAX_SOCKET_STRING];
    fd_t server = bind_socket_resolve_port ("127.0.0.1", "0", my_endpoint);

    curve_client_data_t curve_client_data = {
      fixed_server_public, fixed_client_public, fixed_client_secret};
    void *client_mon;
    void *client = create_and_connect_client (
      my_endpoint, socket_config_curve_client, &curve_client_data, &client_mon);

    fd_t server_accept =
      TEST_ASSERT_SUCCESS_RAW_ERRNO (accept (server, NULL, NULL));

    //  If there is not enough data for a full greeting, just send what we can
    //  Otherwise send greeting first, as expected by the protocol
    uint8_t buf[512];
    if (size >= 64) {
        send (server_accept, (void *) data, 64, MSG_NOSIGNAL);
        data += 64;
        size -= 64;
    }
    recv (server_accept, buf, 64, 0);
    // Then expect HELLO and send WELCOME if there's enough data
    if (size >= 170) {
        recv (server_accept, buf, 202, 0);
        send (server_accept, (void *) data, 170, MSG_NOSIGNAL);
        data += 170;
        size -= 170;
    }
    // Then expect INITIATE and send READY if there's enough data
    if (size >= 72) {
        recv (server_accept, buf, 512, 0);
        send (server_accept, (void *) data, 72, MSG_NOSIGNAL);
        data += 72;
        size -= 72;
    }
    msleep (250);
    for (ssize_t sent = 0; size > 0 && (sent != -1 || errno == EINTR);
         size -= sent > 0 ? sent : 0, data += sent > 0 ? sent : 0)
        sent = send (server_accept, (const char *) data, size, MSG_NOSIGNAL);
    recv (server_accept, buf, 512, MSG_DONTWAIT);
    msleep (250);

    zmq_msg_t msg;
    zmq_msg_init (&msg);
    while (-1 != zmq_msg_recv (&msg, client, ZMQ_DONTWAIT)) {
        zmq_msg_close (&msg);
        zmq_msg_init (&msg);
    }

    close (server_accept);
    close (server);

    test_context_socket_close_zero_linger (client);
    test_context_socket_close_zero_linger (client_mon);
    teardown_test_context ();

    return 0;
}

#ifndef ZMQ_USE_FUZZING_ENGINE
void test_connect_curve_fuzzer ()
{
    uint8_t **data;
    size_t *len, num_cases = 0;
    if (fuzzer_corpus_encode (
          "tests/libzmq-fuzz-corpora/test_connect_curve_fuzzer_seed_corpus",
          &data, &len, &num_cases)
        != 0)
        exit (77);

    while (num_cases-- > 0) {
        TEST_ASSERT_SUCCESS_ERRNO (
          LLVMFuzzerTestOneInput (data[num_cases], len[num_cases]));
        free (data[num_cases]);
    }

    free (data);
    free (len);
}

int main (int argc, char **argv)
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_connect_curve_fuzzer);

    return UNITY_END ();
}
#endif
