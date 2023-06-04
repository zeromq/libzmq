/* SPDX-License-Identifier: MPL-2.0 */

#include "precompiled.hpp"
#include "encoder.hpp"
#include "raw_encoder.hpp"
#include "msg.hpp"

zmq::raw_encoder_t::raw_encoder_t (size_t bufsize_) :
    encoder_base_t<raw_encoder_t> (bufsize_)
{
    //  Write 0 bytes to the batch and go to message_ready state.
    next_step (NULL, 0, &raw_encoder_t::raw_message_ready, true);
}

zmq::raw_encoder_t::~raw_encoder_t ()
{
}

void zmq::raw_encoder_t::raw_message_ready ()
{
    next_step (in_progress ()->data (), in_progress ()->size (),
               &raw_encoder_t::raw_message_ready, true);
}
