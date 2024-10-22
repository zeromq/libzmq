/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_V2_DECODER_HPP_INCLUDED__
#define __ZMQ_V2_DECODER_HPP_INCLUDED__

#include "decoder.hpp"
#include "decoder_allocators.hpp"

namespace zmq
{
//  Decoder for ZMTP/2.x framing protocol. Converts data stream into messages.
//  The class has to inherit from shared_message_memory_allocator because
//  the base class calls allocate in its constructor.
class v2_decoder_t ZMQ_FINAL
    : public decoder_base_t<v2_decoder_t, shared_message_memory_allocator>
{
  public:
    v2_decoder_t (size_t bufsize_, int64_t maxmsgsize_, bool zero_copy_);
    ~v2_decoder_t ();

    //  i_decoder interface.
    msg_t *msg () { return &_in_progress; }

  private:
    int flags_ready (unsigned char const *);
    int one_byte_size_ready (unsigned char const *);
    int eight_byte_size_ready (unsigned char const *);
    int message_ready (unsigned char const *);

    int size_ready (uint64_t size_, unsigned char const *);

    unsigned char _tmpbuf[8];
    unsigned char _msg_flags;
    msg_t _in_progress;

    const bool _zero_copy;
    const int64_t _max_msg_size;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (v2_decoder_t)
};
}

#endif
