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

// String length must be evenly divisible by 5 or must fail with EINVAL.
void test__zmq_z85_decode__invalid__failure (const char *encoded)
{
    errno = 0;
    assert (zmq_z85_decode(NULL, encoded) == NULL);
    assert (zmq_errno () == EINVAL);
}

int main (void)
{
    test__zmq_z85_encode__valid__success ();
    test__zmq_z85_encode__invalid__failure (1);
    test__zmq_z85_encode__invalid__failure (42);

    test__zmq_z85_decode__valid__success ();
    test__zmq_z85_decode__invalid__failure ("01234567");
    test__zmq_z85_decode__invalid__failure ("0");

    return 0;
}
