/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_WS_PROTOCOL_HPP_INCLUDED__
#define __ZMQ_WS_PROTOCOL_HPP_INCLUDED__

#include "stdint.hpp"

#include <string.h>

namespace zmq
{
inline void ws_mask_payload (unsigned char *dest_,
                             const unsigned char *src_,
                             size_t size_,
                             const unsigned char *mask_)
{
    uint32_t mask32;
    memcpy (&mask32, mask_, sizeof (mask32));

    size_t i = 0;
    for (; i + 4 <= size_; i += 4) {
        uint32_t chunk;
        memcpy (&chunk, src_ + i, sizeof (chunk));
        chunk ^= mask32;
        memcpy (dest_ + i, &chunk, sizeof (chunk));
    }

    for (; i < size_; ++i)
        dest_[i] = src_[i] ^ mask_[i & 3];
}

//  Definition of constants for WS transport protocol.
class ws_protocol_t
{
  public:
    //  Message flags.
    enum opcode_t
    {
        opcode_continuation = 0,
        opcode_text = 0x01,
        opcode_binary = 0x02,
        opcode_close = 0x08,
        opcode_ping = 0x09,
        opcode_pong = 0xA
    };

    enum
    {
        more_flag = 1,
        command_flag = 2
    };
};
}

#endif
