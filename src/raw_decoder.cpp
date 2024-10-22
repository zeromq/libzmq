/* SPDX-License-Identifier: MPL-2.0 */

#include "precompiled.hpp"
#include <stdlib.h>
#include <string.h>

#include "raw_decoder.hpp"
#include "err.hpp"

zmq::raw_decoder_t::raw_decoder_t (size_t bufsize_) : _allocator (bufsize_, 1)
{
    const int rc = _in_progress.init ();
    errno_assert (rc == 0);
}

zmq::raw_decoder_t::~raw_decoder_t ()
{
    const int rc = _in_progress.close ();
    errno_assert (rc == 0);
}

void zmq::raw_decoder_t::get_buffer (unsigned char **data_, size_t *size_)
{
    *data_ = _allocator.allocate ();
    *size_ = _allocator.size ();
}

int zmq::raw_decoder_t::decode (const uint8_t *data_,
                                size_t size_,
                                size_t &bytes_used_)
{
    const int rc =
      _in_progress.init (const_cast<unsigned char *> (data_), size_,
                         shared_message_memory_allocator::call_dec_ref,
                         _allocator.buffer (), _allocator.provide_content ());

    // if the buffer serves as memory for a zero-copy message, release it
    // and allocate a new buffer in get_buffer for the next decode
    if (_in_progress.is_zcmsg ()) {
        _allocator.advance_content ();
        _allocator.release ();
    }

    errno_assert (rc != -1);
    bytes_used_ = size_;
    return 1;
}
