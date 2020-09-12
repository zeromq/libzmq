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
#include "testutil_unity.hpp"

#ifdef ZMQ_DISCONNECT_MSG
#define LAST_OPTION ZMQ_DISCONNECT_MSG
#else
#define LAST_OPTION ZMQ_BINDTODEVICE
#endif

extern "C" int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
    int option;
    void *ctx = zmq_ctx_new ();
    TEST_ASSERT_NOT_NULL (ctx);
    void *server = zmq_socket (ctx, ZMQ_XPUB);
    TEST_ASSERT_NOT_NULL (server);

    if (!size)
        return 0;

    for (option = ZMQ_AFFINITY; option <= LAST_OPTION; ++option) {
        uint8_t out[8192];
        size_t out_size = 8192;

        zmq_setsockopt (server, option, data, size);
        zmq_getsockopt (server, option, out, &out_size);
    }

    zmq_close (server);
    zmq_ctx_term (ctx);

    return 0;
}

#ifndef ZMQ_USE_FUZZING_ENGINE
void test_socket_options_fuzzer ()
{
    uint8_t **data;
    size_t *len, num_cases = 0;
    if (fuzzer_corpus_encode (
          "tests/libzmq-fuzz-corpora/test_socket_options_fuzzer_seed_corpus",
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
    RUN_TEST (test_socket_options_fuzzer);

    return UNITY_END ();
}
#endif
