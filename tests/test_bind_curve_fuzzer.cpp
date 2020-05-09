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

#include <string.h>

#include "testutil.hpp"
#include "testutil_security.hpp"

// Test that the ZMTP engine handles invalid handshake when binding
// https://rfc.zeromq.org/spec/37/
extern "C" int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
    const char *fixed_client_public =
      "{{k*81)yMWEF{/BxdMd[5RL^qRFxBgoL<8m.D^KD";
    const char *fixed_server_secret =
      "T}t5GLq%&Qm1)y3ywu-}pY3KEA//{^Ut!M1ut+B4";
    void *handler;
    void *zap_thread;
    void *server;
    void *server_mon;
    char my_endpoint[MAX_SOCKET_STRING];

    setup_test_context ();
    memcpy (valid_client_public, fixed_client_public, 41);
    setup_context_and_server_side (
      &handler, &zap_thread, &server, &server_mon, my_endpoint, &zap_handler,
      &socket_config_curve_server, (void *) fixed_server_secret);
    fd_t client = connect_socket (my_endpoint);

    //  If there is not enough data for a full greeting, just send what we can
    //  Otherwise send greeting first, as expected by the protocol
    uint8_t buf[512];
    if (size >= 64) {
        send (client, (void *) data, 64, MSG_NOSIGNAL);
        data += 64;
        size -= 64;
    }
    recv (client, buf, 64, 0);
    // Then send HELLO and expect WELCOME if there's enough data
    if (size >= 202) {
        send (client, (void *) data, 202, MSG_NOSIGNAL);
        data += 202;
        size -= 202;
        recv (client, buf, 170, MSG_DONTWAIT);
    }
    // Then send READY and expect INITIATE if there's enough data
    if (size >= 301) {
        send (client, (void *) data, 301, MSG_NOSIGNAL);
        data += 301;
        size -= 301;
        recv (client, buf, 512, MSG_DONTWAIT);
    }
    msleep (250);
    for (ssize_t sent = 0; size > 0 && (sent != -1 || errno == EINTR);
         size -= sent > 0 ? sent : 0, data += sent > 0 ? sent : 0)
        sent = send (client, (const char *) data, size, MSG_NOSIGNAL);
    msleep (250);

    close (client);

    shutdown_context_and_server_side (zap_thread, server, server_mon, handler);
    teardown_test_context ();

    return 0;
}

#ifndef ZMQ_USE_FUZZING_ENGINE
void test_bind_curve_fuzzer ()
{
    uint8_t **data;
    size_t *len, num_cases = 0;
    if (fuzzer_corpus_encode ("tests/fuzzer_corpora/test_bind_curve_fuzzer.txt",
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
    RUN_TEST (test_bind_curve_fuzzer);

    return UNITY_END ();
}
#endif
