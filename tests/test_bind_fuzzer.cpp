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

#include <string>

#include "testutil.hpp"
#include "testutil_unity.hpp"

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

// Test that zmq_bind can handle malformed strings
extern "C" int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
    //  This test might create socket files, so move to /tmp to avoid clobbering
    //  the working directory with random filenames
    char *pwd = (char *) malloc (PATH_MAX + 1);
    TEST_ASSERT_NOT_NULL (pwd);
    TEST_ASSERT_NOT_NULL (getcwd (pwd, PATH_MAX + 1));
    TEST_ASSERT_SUCCESS_ERRNO (chdir ("/tmp"));

    setup_test_context ();
    std::string my_endpoint (reinterpret_cast<const char *> (data), size);
    void *socket = test_context_socket (ZMQ_PUB);
    zmq_bind (socket, my_endpoint.c_str ());

    test_context_socket_close_zero_linger (socket);
    teardown_test_context ();
    TEST_ASSERT_SUCCESS_ERRNO (chdir (pwd));
    free (pwd);

    return 0;
}

#ifndef ZMQ_USE_FUZZING_ENGINE
void test_bind_fuzzer ()
{
    uint8_t **data;
    size_t *len, num_cases = 0;
    if (fuzzer_corpus_encode (
          "tests/libzmq-fuzz-corpora/test_bind_fuzzer_seed_corpus", &data, &len,
          &num_cases)
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
    RUN_TEST (test_bind_fuzzer);

    return UNITY_END ();
}
#endif
