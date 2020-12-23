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

    _is_binary = false;

    if (in_progress ()->is_ping ())
        _tmp_buf[offset++] = 0x80 | zmq::ws_protocol_t::opcode_ping;
    else if (in_progress ()->is_pong ())
        _tmp_buf[offset++] = 0x80 | zmq::ws_protocol_t::opcode_pong;
    else if (in_progress ()->is_close_cmd ())
        _tmp_buf[offset++] = 0x80 | zmq::ws_protocol_t::opcode_close;
    else {
        _tmp_buf[offset++] = 0x82; // Final | binary
        _is_binary = true;
    }

    _tmp_buf[offset] = _must_mask ? 0x80 : 0x00;

    size_t size = in_progress ()->size ();
    if (_is_binary)
        size++;
    //  TODO: create an opcode for subscribe/cancel
    if (in_progress ()->is_subscribe () || in_progress ()->is_cancel ())
        size++;

    if (size <= 125)
        _tmp_buf[offset++] |= static_cast<unsigned char> (size & 127);
    else if (size <= 0xFFFF) {
        _tmp_buf[offset++] |= 126;
        _tmp_buf[offset++] = static_cast<unsigned char> ((size >> 8) & 0xFF);
        _tmp_buf[offset++] = static_cast<unsigned char> (size & 0xFF);
    } else {
        _tmp_buf[offset++] |= 127;
        put_uint64 (_tmp_buf + offset, size);
        offset += 8;
    }

    if (_must_mask) {
        const uint32_t random = generate_random ();
        put_uint32 (_tmp_buf + offset, random);
        put_uint32 (_mask, random);
        offset += 4;
    }

    int mask_index = 0;
    if (_is_binary) {
        //  Encode flags.
        unsigned char protocol_flags = 0;
        if (in_progress ()->flags () & msg_t::more)
            protocol_flags |= ws_protocol_t::more_flag;
        if (in_progress ()->flags () & msg_t::command)
            protocol_flags |= ws_protocol_t::command_flag;

        _tmp_buf[offset++] =
          _must_mask ? protocol_flags ^ _mask[mask_index++] : protocol_flags;
    }

    //  Encode the subscribe/cancel byte.
    //  TODO: remove once there is an opcode for subscribe/cancel
    if (in_progress ()->is_subscribe ())
        _tmp_buf[offset++] = _must_mask ? 1 ^ _mask[mask_index++] : 1;
    else if (in_progress ()->is_cancel ())
        _tmp_buf[offset++] = _must_mask ? 0 ^ _mask[mask_index++] : 0;

    next_step (_tmp_buf, offset, &ws_encoder_t::size_ready, false);
}

void zmq::ws_encoder_t::size_ready ()
{
    if (_must_mask) {
        assert (in_progress () != &_masked_msg);
        const size_t size = in_progress ()->size ();

        unsigned char *src =
          static_cast<unsigned char *> (in_progress ()->data ());
        unsigned char *dest = src;

        //  If msg is shared or data is constant we cannot mask in-place, allocate a new msg for it
        if (in_progress ()->flags () & msg_t::shared
            || in_progress ()->is_cmsg ()) {
            _masked_msg.close ();
            _masked_msg.init_size (size);
            dest = static_cast<unsigned char *> (_masked_msg.data ());
        }

        int mask_index = 0;
        if (_is_binary)
            ++mask_index;
        //  TODO: remove once there is an opcode for subscribe/cancel
        if (in_progress ()->is_subscribe () || in_progress ()->is_cancel ())
            ++mask_index;
        for (size_t i = 0; i < size; ++i, mask_index++)
            dest[i] = src[i] ^ _mask[mask_index % 4];

        next_step (dest, size, &ws_encoder_t::message_ready, true);
    } else {
        next_step (in_progress ()->data (), in_progress ()->size (),
                   &ws_encoder_t::message_ready, true);
    }
}
