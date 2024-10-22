/* SPDX-License-Identifier: MPL-2.0 */

#ifdef ZMQ_USE_FUZZING_ENGINE
#include <fuzzer/FuzzedDataProvider.h>
#endif

#include <string>
#include <stdlib.h>

#include "testutil.hpp"
#include "testutil_unity.hpp"

extern "C" int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
    uint8_t *secret_key;

    if (size < 5)
        return 0;

    // As per API definition, input must be divisible by 5, so truncate it if it's not
    size -= size % 5;
    // As per API definition, the destination must be at least 0.8 times the input data
    TEST_ASSERT_NOT_NULL (secret_key = (uint8_t *) malloc (size * 4 / 5));

    std::string z85_secret_key (reinterpret_cast<const char *> (data), size);
    zmq_z85_decode (secret_key, z85_secret_key.c_str ());

    free (secret_key);

    return 0;
}

#ifndef ZMQ_USE_FUZZING_ENGINE
void test_z85_decode_fuzzer ()
{
    uint8_t **data;
    size_t *len, num_cases = 0;
    if (fuzzer_corpus_encode (
          "tests/libzmq-fuzz-corpora/test_z85_decode_fuzzer_seed_corpus", &data,
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
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_z85_decode_fuzzer);

    return UNITY_END ();
}
#endif
