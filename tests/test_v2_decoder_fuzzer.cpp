/* SPDX-License-Identifier: MPL-2.0 */

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <vector>

#include <zmq.h>

#include "../src/v2_decoder.hpp"

namespace
{
const size_t buffer_size = 4096;
const size_t max_fuzz_size = 64 * 1024;
const int64_t max_msg_size = 64 * 1024;

void decode_stream (const uint8_t *data, size_t size, bool zero_copy)
{
    zmq::v2_decoder_t decoder (buffer_size, max_msg_size, zero_copy);
    size_t offset = 0;

    while (offset < size) {
        unsigned char *buffer = NULL;
        size_t available = 0;
        decoder.get_buffer (&buffer, &available);
        const size_t chunk_size = std::min (size - offset, available);
        if (!chunk_size)
            break;

        std::memcpy (buffer, data + offset, chunk_size);
        size_t used = 0;
        const int rc = decoder.decode (buffer, chunk_size, used);
        if (rc < 0 || !used)
            break;
        offset += used;
    }
}

std::vector<uint8_t> make_frame (const uint8_t *data,
                                 size_t size,
                                 bool large_length)
{
        const size_t payload_size =
            large_length ? std::max (size_t (128), std::min (size, size_t (2048)))
                   : std::min (size, size_t (255));
    const uint8_t flags = size ? data[0] & 0x05 : 0;
    std::vector<uint8_t> frame;

    if (large_length) {
        frame.push_back (flags | 0x02);
        for (int shift = 56; shift >= 0; shift -= 8)
            frame.push_back (static_cast<uint8_t> (payload_size >> shift));
    } else {
        frame.push_back (flags);
        frame.push_back (static_cast<uint8_t> (payload_size));
    }

    for (size_t i = 0; i < payload_size; ++i)
        frame.push_back (size ? data[i % size] : static_cast<uint8_t> (i));

    return frame;
}
}

extern "C" int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
    size = std::min (size, max_fuzz_size);

    decode_stream (data, size, false);

    const std::vector<uint8_t> short_frame = make_frame (data, size, false);
    decode_stream (short_frame.data (), short_frame.size (), false);

    const std::vector<uint8_t> long_frame = make_frame (data, size, true);
    decode_stream (long_frame.data (), long_frame.size (), false);
    decode_stream (long_frame.data (), long_frame.size (), true);

    std::vector<uint8_t> frame_sequence = short_frame;
    frame_sequence.insert (frame_sequence.end (), long_frame.begin (),
                           long_frame.end ());
    decode_stream (frame_sequence.data (), frame_sequence.size (), true);

    return 0;
}