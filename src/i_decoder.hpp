/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_I_DECODER_HPP_INCLUDED__
#define __ZMQ_I_DECODER_HPP_INCLUDED__

#include "macros.hpp"
#include "stdint.hpp"

namespace zmq
{
class msg_t;

//  Interface to be implemented by message decoder.

class i_decoder
{
  public:
    virtual ~i_decoder () ZMQ_DEFAULT;

    virtual void get_buffer (unsigned char **data_, size_t *size_) = 0;

    virtual void resize_buffer (size_t) = 0;
    //  Decodes data pointed to by data_.
    //  When a message is decoded, 1 is returned.
    //  When the decoder needs more data, 0 is returned.
    //  On error, -1 is returned and errno is set accordingly.
    virtual int
    decode (const unsigned char *data_, size_t size_, size_t &processed_) = 0;

    virtual msg_t *msg () = 0;
};
}

#endif
