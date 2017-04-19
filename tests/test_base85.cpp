/*
    Copyright (c) 2016 Contributors as noted in the AUTHORS file

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

// Test vector: rfc.zeromq.org/spec:32/Z85
void test__zmq_z85_encode__valid__success ()
{
    static const size_t size = 8;
    static const size_t length = size * 5 / 4;
    static const uint8_t decoded[size] = {
        0x86, 0x4F, 0xD2, 0x6F, 0xB5, 0x59, 0xF7, 0x5B
    };
    static const char expected[length + 1] = "HelloWorld";
    char out_encoded[length + 1] = { 0 };

    errno = 0;
    assert (zmq_z85_encode(out_encoded, decoded, size) != NULL);
    assert (streq (out_encoded, expected));
    assert (zmq_errno () == 0);
}

// Buffer length must be evenly divisible by 4 or must fail with EINVAL.
void test__zmq_z85_encode__invalid__failure (size_t size)
{
    errno = 0;
    assert (zmq_z85_encode(NULL, NULL, size) == NULL);
    assert (zmq_errno () == EINVAL);
}

// Test vector: rfc.zeromq.org/spec:32/Z85
void test__zmq_z85_decode__valid__success ()
{
    static const size_t size = 10 * 4 / 5;
    static const uint8_t expected[size] = {
        0x86, 0x4F, 0xD2, 0x6F, 0xB5, 0x59, 0xF7, 0x5B
    };
    static const char* encoded = "HelloWorld";
    uint8_t out_decoded[size] = { 0 };

    errno = 0;
    assert (zmq_z85_decode(out_decoded, encoded) != NULL);
    assert (zmq_errno () == 0);
    assert (memcmp (out_decoded, expected, size) == 0);
}

// Invalid input data must fail with EINVAL.
template<size_t SIZE>
void test__zmq_z85_decode__invalid__failure (const char (&encoded)[SIZE])
{
    uint8_t decoded[SIZE * 4 / 5 + 1];
    errno = 0;
    assert (zmq_z85_decode(decoded, encoded) == NULL);
    assert (zmq_errno () == EINVAL);
}


// call zmq_z85_encode, then zmq_z85_decode, and compare the results with the original
template<size_t SIZE>
void test__zmq_z85_encode__zmq_z85_decode__roundtrip(const uint8_t (&test_data)[SIZE])
{
    char test_data_z85[SIZE * 5 / 4 + 1];
    char *res1 = zmq_z85_encode(test_data_z85, test_data, SIZE);
    assert(res1 != NULL);

    uint8_t test_data_decoded[SIZE];
    uint8_t *res2 = zmq_z85_decode(test_data_decoded, test_data_z85);
    assert(res2 != NULL);

    int res3 = memcmp(test_data, test_data_decoded, SIZE);
    assert(res3 == 0);
}

// call zmq_z85_encode, then zmq_z85_decode, and compare the results with the original
template<size_t SIZE>
void test__zmq_z85_decode__zmq_z85_encode__roundtrip(const char (&test_data)[SIZE])
{
    const size_t decoded_size = (SIZE - 1) * 4 / 5;
    uint8_t test_data_decoded[decoded_size];
    uint8_t *res1 = zmq_z85_decode(test_data_decoded, test_data);
    assert(res1 != NULL);

    char test_data_z85[SIZE];
    char *res2 = zmq_z85_encode(test_data_z85, test_data_decoded, decoded_size);
    assert(res2 != NULL);

    int res3 = memcmp(test_data, test_data_z85, SIZE);
    assert(res3 == 0);
}


int main (void)
{
    test__zmq_z85_encode__valid__success ();
    test__zmq_z85_encode__invalid__failure (1);
    test__zmq_z85_encode__invalid__failure (42);

    test__zmq_z85_decode__valid__success ();
    // String length must be evenly divisible by 5 or must fail with EINVAL.
    test__zmq_z85_decode__invalid__failure ("01234567");
    test__zmq_z85_decode__invalid__failure ("0");

    // decode invalid data with the maximum representable value
    test__zmq_z85_decode__invalid__failure ("#####");

    // decode invalid data with the minimum value beyond the limit
    // "%nSc0" is 0xffffffff
    test__zmq_z85_decode__invalid__failure ("%nSc1");

    // decode invalid data with an invalid character in the range of valid
    // characters
    test__zmq_z85_decode__invalid__failure ("####\0047");

    // decode invalid data with an invalid character just below the range of valid
    // characters
    test__zmq_z85_decode__invalid__failure ("####\0200");

    // decode invalid data with an invalid character just above the range of valid
    // characters
    test__zmq_z85_decode__invalid__failure ("####\0037");

    // round-trip encoding and decoding with minimum value
    {
      const uint8_t test_data[] = {0x00, 0x00, 0x00, 0x00};
      test__zmq_z85_encode__zmq_z85_decode__roundtrip(test_data);
    }
    // round-trip encoding and decoding with maximum value
    {
      const uint8_t test_data[] = {0xff, 0xff, 0xff, 0xff};
      test__zmq_z85_encode__zmq_z85_decode__roundtrip(test_data);
    }

    test__zmq_z85_decode__zmq_z85_encode__roundtrip("r^/rM9M=rMToK)63O8dCvd9D<PY<7iGlC+{BiSnG");

    return 0;
}
