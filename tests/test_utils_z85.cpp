/*
    Copyright (c) 2007-2015 Contributors as noted in the AUTHORS file

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

#include <cassert>
#include <cstring>
#include <zmq.h>

template<size_t SIZE>
void test_roundtrip(const uint8_t (&test_data)[SIZE])
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

int main(void) {
  // round-trip encoding and decoding
  {
    const uint8_t test_data[] = {0x01, 0x02, 0x03, 0x04};
    test_roundtrip(test_data);
  }
  {
    const uint8_t test_data[] = {0xff, 0xff, 0xff, 0xff};
    test_roundtrip(test_data);
  }

  // decode invalid data of wrong length that is otherwise valid
  {
    const char test_data_encoded[] = "0123";
    uint8_t test_data_decoded[4];
    uint8_t *res = zmq_z85_decode(test_data_decoded, test_data_encoded);
    assert(res == NULL);
  }

  // decode invalid data with the maximum representable value
  {
    const char test_data_encoded[] = "#####";
    uint8_t test_data_decoded[4];
    uint8_t *res = zmq_z85_decode(test_data_decoded, test_data_encoded);
    assert(res == NULL);
  }

  //  // decode invalid data with the minimum value beyond the limit
  {
    // "%nSc0" is 0xffffffff
    const char test_data_encoded[] = "%nSc1";
    uint8_t test_data_decoded[4];
    uint8_t *res = zmq_z85_decode(test_data_decoded, test_data_encoded);
    assert(res == NULL);
  }

  // decode invalid data with an invalid character in the range of valid
  // characters
  {
    const char test_data_encoded[] = "####\0047";
    uint8_t test_data_decoded[4];
    uint8_t *res = zmq_z85_decode(test_data_decoded, test_data_encoded);
    assert(res == NULL);
  }

  // decode invalid data with an invalid character just below the range of valid
  // characters
  {
    const char test_data_encoded[] = "####\0200";
    uint8_t test_data_decoded[4];
    uint8_t *res = zmq_z85_decode(test_data_decoded, test_data_encoded);
    assert(res == NULL);
  }

  // decode invalid data with an invalid character just above the range of valid
  // characters
  {
    const char test_data_encoded[] = "####\0037";
    uint8_t test_data_decoded[4];
    uint8_t *res = zmq_z85_decode(test_data_decoded, test_data_encoded);
    assert(res == NULL);
  }
}
