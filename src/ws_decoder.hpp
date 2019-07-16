/*
    Copyright (c) 2007-2019 Contributors as noted in the AUTHORS file

    This file is part of libzmq, the ZeroMQ core engine in C++.

    libzmq is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License (LGPL) as published
    by the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    As a special exception, the Contributors give you permission to link
    this library with independent modules to produce an executable,
    regardless of the license terms of these independent modules, and to
    copy and distribute the resulting executable under terms of your choice,
    provided that you also meet, for each linked independent module, the
    terms and conditions of the license of that module. An independent
    module is a module which is not derived from or based on this library.
    If you modify this library, you must extend this exception to your
    version of the library.

    libzmq is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
    FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
    License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

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
class ws_decoder_t
    : public decoder_base_t<ws_decoder_t, shared_message_memory_allocator>
{
  public:
    ws_decoder_t (size_t bufsize_,
                  int64_t maxmsgsize_,
                  bool zero_copy_,
                  bool must_mask_);
    virtual ~ws_decoder_t ();

    //  i_decoder interface.
    virtual msg_t *msg () { return &_in_progress; }

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

    ws_decoder_t (const ws_decoder_t &);
    void operator= (const ws_decoder_t &);
};
}

#endif
