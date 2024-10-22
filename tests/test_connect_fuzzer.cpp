/* SPDX-License-Identifier: MPL-2.0 */

#ifdef ZMQ_USE_FUZZING_ENGINE
#include <fuzzer/FuzzedDataProvider.h>
#endif

#include <string>

#include "testutil.hpp"
#include "testutil_unity.hpp"

// Test that zmq_connect can handle malformed strings
extern "C" int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
    setup_test_context ();
    std::string my_endpoint (reinterpret_cast<const char *> (data), size);
    void *socket = test_context_socket (ZMQ_PUB);
    zmq_connect (socket, my_endpoint.c_str ());

    test_context_socket_close_zero_linger (socket);
    teardown_test_context ();

    return 0;
}

#ifndef ZMQ_USE_FUZZING_ENGINE
void test_connect_fuzzer ()
{
    uint8_t **data;
    size_t *len, num_cases = 0;
    if (fuzzer_corpus_encode (
          "tests/libzmq-fuzz-corpora/test_connect_fuzzer_seed_corpus", &data,
          &len, &num_cases)
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
    LIBZMQ_UNUSED (argc);
    LIBZMQ_UNUSED (argv);

    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_connect_fuzzer);

    return UNITY_END ();
}
#endif
