/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_RAW_ENCODER_HPP_INCLUDED__
#define __ZMQ_RAW_ENCODER_HPP_INCLUDED__

#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include "encoder.hpp"

namespace zmq
{
//  Encoder for 0MQ framing protocol. Converts messages into data batches.

class raw_encoder_t ZMQ_FINAL : public encoder_base_t<raw_encoder_t>
{
  public:
    raw_encoder_t (size_t bufsize_);
    ~raw_encoder_t ();

  private:
    void raw_message_ready ();

    ZMQ_NON_COPYABLE_NOR_MOVABLE (raw_encoder_t)
};
}

#endif
