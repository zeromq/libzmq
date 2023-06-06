/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_V2_ENCODER_HPP_INCLUDED__
#define __ZMQ_V2_ENCODER_HPP_INCLUDED__

#include "encoder.hpp"

namespace zmq
{
//  Encoder for 0MQ framing protocol. Converts messages into data stream.

class v2_encoder_t ZMQ_FINAL : public encoder_base_t<v2_encoder_t>
{
  public:
    v2_encoder_t (size_t bufsize_);
    ~v2_encoder_t ();

  private:
    void size_ready ();
    void message_ready ();

    //  flags byte + size byte (or 8 bytes) + sub/cancel byte
    unsigned char _tmp_buf[10];

    ZMQ_NON_COPYABLE_NOR_MOVABLE (v2_encoder_t)
};
}

#endif
