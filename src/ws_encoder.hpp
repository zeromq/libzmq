/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_WS_ENCODER_HPP_INCLUDED__
#define __ZMQ_WS_ENCODER_HPP_INCLUDED__

#include "encoder.hpp"

namespace zmq
{
//  Encoder for web socket framing protocol. Converts messages into data stream.

class ws_encoder_t ZMQ_FINAL : public encoder_base_t<ws_encoder_t>
{
  public:
    ws_encoder_t (size_t bufsize_, bool must_mask_);
    ~ws_encoder_t ();

  private:
    void size_ready ();
    void message_ready ();

    unsigned char _tmp_buf[16];
    bool _must_mask;
    unsigned char _mask[4];
    msg_t _masked_msg;
    bool _is_binary;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (ws_encoder_t)
};
}

#endif
