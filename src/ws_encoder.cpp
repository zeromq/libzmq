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

#include "precompiled.hpp"
#include "ws_protocol.hpp"
#include "ws_encoder.hpp"
#include "msg.hpp"
#include "likely.hpp"
#include "wire.hpp"
#include "random.hpp"

#include <limits.h>

zmq::ws_encoder_t::ws_encoder_t (size_t bufsize_, bool must_mask_) :
    encoder_base_t<ws_encoder_t> (bufsize_),
    _must_mask (must_mask_)
{
    //  Write 0 bytes to the batch and go to message_ready state.
    next_step (NULL, 0, &ws_encoder_t::message_ready, true);
    _masked_msg.init ();
}

zmq::ws_encoder_t::~ws_encoder_t ()
{
    _masked_msg.close ();
}

void zmq::ws_encoder_t::message_ready ()
{
    int offset = 0;

    // TODO: it might be close/ping/pong, which should be different op code
    _tmp_buf[offset++] = 0x82; // Final | binary
    _tmp_buf[offset] = _must_mask ? 0x80 : 0x00;

    size_t size = in_progress ()->size ();
    size++; // TODO: check if binary

    if (size <= 125)
        _tmp_buf[offset++] |= (unsigned char) (size & 127);
    else if (size <= 0xFFFF) {
        _tmp_buf[offset++] |= 126;
        _tmp_buf[offset++] = (unsigned char) ((size >> 8) & 0xFF);
        _tmp_buf[offset++] = (unsigned char) (size & 0xFF);
    } else {
        _tmp_buf[offset++] |= 127;
        put_uint64 (_tmp_buf + offset, size);
        offset += 8;
    }

    if (_must_mask) {
        uint32_t random = generate_random ();
        put_uint32 (_tmp_buf + offset, random);
        put_uint32 (_mask, random);
        offset += 4;
    }

    // TODO: check if binary

    //  Encode flags.
    unsigned char protocol_flags = 0;
    if (in_progress ()->flags () & msg_t::more)
        protocol_flags |= ws_protocol_t::more_flag;
    if (in_progress ()->flags () & msg_t::command)
        protocol_flags |= ws_protocol_t::command_flag;

    _tmp_buf[offset++] =
      _must_mask ? protocol_flags ^ _mask[0] : protocol_flags;

    next_step (_tmp_buf, offset, &ws_encoder_t::size_ready, false);
}

void zmq::ws_encoder_t::size_ready ()
{
    if (_must_mask) {
        assert (in_progress () != &_masked_msg);
        size_t size = in_progress ()->size ();

        _masked_msg.close ();
        _masked_msg.init_size (size);

        int mask_index = 1; // TODO: check if binary message
        unsigned char *dest = (unsigned char *) _masked_msg.data ();
        unsigned char *src = (unsigned char *) in_progress ()->data ();
        for (size_t i = 0; i < in_progress ()->size (); ++i, mask_index++)
            dest[i] = src[i] ^ _mask[mask_index % 4];

        next_step (_masked_msg.data (), _masked_msg.size (),
                   &ws_encoder_t::message_ready, true);
    } else {
        next_step (in_progress ()->data (), in_progress ()->size (),
                   &ws_encoder_t::message_ready, true);
    }
}
