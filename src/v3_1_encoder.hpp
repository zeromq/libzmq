/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_V3_1_ENCODER_HPP_INCLUDED__
#define __ZMQ_V3_1_ENCODER_HPP_INCLUDED__

#include "encoder.hpp"
#include "msg.hpp"

namespace zmq
{
//  Encoder for 0MQ framing protocol. Converts messages into data stream.

class v3_1_encoder_t ZMQ_FINAL : public encoder_base_t<v3_1_encoder_t>
{
  public:
    v3_1_encoder_t (size_t bufsize_);
    ~v3_1_encoder_t () ZMQ_FINAL;

  private:
    void size_ready ();
    void message_ready ();

    unsigned char _tmp_buf[9 + zmq::msg_t::sub_cmd_name_size];

    ZMQ_NON_COPYABLE_NOR_MOVABLE (v3_1_encoder_t)
};
}

#endif
