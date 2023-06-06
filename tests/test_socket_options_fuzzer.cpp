/* SPDX-License-Identifier: MPL-2.0 */

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
