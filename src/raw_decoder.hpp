/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_RAW_DECODER_HPP_INCLUDED__
#define __ZMQ_RAW_DECODER_HPP_INCLUDED__

#include "msg.hpp"
#include "i_decoder.hpp"
#include "stdint.hpp"
#include "decoder_allocators.hpp"

namespace zmq
{
//  Decoder for 0MQ v1 framing protocol. Converts data stream into messages.

class raw_decoder_t ZMQ_FINAL : public i_decoder
{
  public:
    raw_decoder_t (size_t bufsize_);
    ~raw_decoder_t ();

    //  i_decoder interface.

    void get_buffer (unsigned char **data_, size_t *size_);

    int decode (const unsigned char *data_, size_t size_, size_t &bytes_used_);

    msg_t *msg () { return &_in_progress; }

    void resize_buffer (size_t) {}

  private:
    msg_t _in_progress;

    shared_message_memory_allocator _allocator;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (raw_decoder_t)
};
}

#endif
