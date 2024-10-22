/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_WS_DECODER_HPP_INCLUDED__
#define __ZMQ_WS_DECODER_HPP_INCLUDED__

#include "decoder.hpp"
#include "decoder_allocators.hpp"
#include "ws_protocol.hpp"

namespace zmq
{
//  Decoder for Web socket framing protocol. Converts data stream into messages.
//  The class has to inherit from shared_message_memory_allocator because
//  the base class calls allocate in its constructor.
class ws_decoder_t ZMQ_FINAL
    : public decoder_base_t<ws_decoder_t, shared_message_memory_allocator>
{
  public:
    ws_decoder_t (size_t bufsize_,
                  int64_t maxmsgsize_,
                  bool zero_copy_,
                  bool must_mask_);
    ~ws_decoder_t ();

    //  i_decoder interface.
    msg_t *msg () { return &_in_progress; }

  private:
    int opcode_ready (unsigned char const *);
    int size_first_byte_ready (unsigned char const *);
    int short_size_ready (unsigned char const *);
    int long_size_ready (unsigned char const *);
    int mask_ready (unsigned char const *);
    int flags_ready (unsigned char const *);
    int message_ready (unsigned char const *);

    int size_ready (unsigned char const *);

    unsigned char _tmpbuf[8];
    unsigned char _msg_flags;
    msg_t _in_progress;

    const bool _zero_copy;
    const int64_t _max_msg_size;
    const bool _must_mask;
    uint64_t _size;
    zmq::ws_protocol_t::opcode_t _opcode;
    unsigned char _mask[4];

    ZMQ_NON_COPYABLE_NOR_MOVABLE (ws_decoder_t)
};
}

#endif
