/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_WS_PROTOCOL_HPP_INCLUDED__
#define __ZMQ_WS_PROTOCOL_HPP_INCLUDED__

namespace zmq
{
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
