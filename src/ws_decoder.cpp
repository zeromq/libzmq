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
#include <stdlib.h>
#include <string.h>
#include <cmath>

#include "ws_protocol.hpp"
#include "ws_decoder.hpp"
#include "likely.hpp"
#include "wire.hpp"
#include "err.hpp"

zmq::ws_decoder_t::ws_decoder_t (size_t bufsize_,
                                 int64_t maxmsgsize_,
                                 bool zero_copy_,
                                 bool must_mask_) :
    decoder_base_t<ws_decoder_t, shared_message_memory_allocator> (bufsize_),
    _msg_flags (0),
    _zero_copy (zero_copy_),
    _max_msg_size (maxmsgsize_),
    _must_mask (must_mask_),
    _size (0)
{
    memset (_tmpbuf, 0, sizeof (_tmpbuf));
    int rc = _in_progress.init ();
    errno_assert (rc == 0);

    //  At the beginning, read one byte and go to opcode_ready state.
    next_step (_tmpbuf, 1, &ws_decoder_t::opcode_ready);
}

zmq::ws_decoder_t::~ws_decoder_t ()
{
    const int rc = _in_progress.close ();
    errno_assert (rc == 0);
}

int zmq::ws_decoder_t::opcode_ready (unsigned char const *)
{
    const bool final = (_tmpbuf[0] & 0x80) != 0; // final bit
    if (!final)
        return -1; // non final messages are not supported

    _opcode = static_cast<zmq::ws_protocol_t::opcode_t> (_tmpbuf[0] & 0xF);

    _msg_flags = 0;

    switch (_opcode) {
        case zmq::ws_protocol_t::opcode_binary:
            break;
        case zmq::ws_protocol_t::opcode_close:
            _msg_flags = msg_t::command | msg_t::close_cmd;
            break;
        case zmq::ws_protocol_t::opcode_ping:
            _msg_flags = msg_t::ping | msg_t::command;
            break;
        case zmq::ws_protocol_t::opcode_pong:
            _msg_flags = msg_t::pong | msg_t::command;
            break;
        default:
            return -1;
    }

    next_step (_tmpbuf, 1, &ws_decoder_t::size_first_byte_ready);

    return 0;
}

int zmq::ws_decoder_t::size_first_byte_ready (unsigned char const *read_from_)
{
    const bool is_masked = (_tmpbuf[0] & 0x80) != 0;

    if (is_masked != _must_mask) // wrong mask value
        return -1;

    _size = static_cast<uint64_t> (_tmpbuf[0] & 0x7F);

    if (_size < 126) {
        if (_must_mask)
            next_step (_tmpbuf, 4, &ws_decoder_t::mask_ready);
        else if (_opcode == ws_protocol_t::opcode_binary) {
            if (_size == 0)
                return -1;
            next_step (_tmpbuf, 1, &ws_decoder_t::flags_ready);
        } else
            return size_ready (read_from_);
    } else if (_size == 126)
        next_step (_tmpbuf, 2, &ws_decoder_t::short_size_ready);
    else
        next_step (_tmpbuf, 8, &ws_decoder_t::long_size_ready);

    return 0;
}


int zmq::ws_decoder_t::short_size_ready (unsigned char const *read_from_)
{
    _size = (_tmpbuf[0] << 8) | _tmpbuf[1];

    if (_must_mask)
        next_step (_tmpbuf, 4, &ws_decoder_t::mask_ready);
    else if (_opcode == ws_protocol_t::opcode_binary) {
        if (_size == 0)
            return -1;
        next_step (_tmpbuf, 1, &ws_decoder_t::flags_ready);
    } else
        return size_ready (read_from_);

    return 0;
}

int zmq::ws_decoder_t::long_size_ready (unsigned char const *read_from_)
{
    //  The payload size is encoded as 64-bit unsigned integer.
    //  The most significant byte comes first.
    _size = get_uint64 (_tmpbuf);

    if (_must_mask)
        next_step (_tmpbuf, 4, &ws_decoder_t::mask_ready);
    else if (_opcode == ws_protocol_t::opcode_binary) {
        if (_size == 0)
            return -1;
        next_step (_tmpbuf, 1, &ws_decoder_t::flags_ready);
    } else
        return size_ready (read_from_);

    return 0;
}

int zmq::ws_decoder_t::mask_ready (unsigned char const *read_from_)
{
    memcpy (_mask, _tmpbuf, 4);

    if (_opcode == ws_protocol_t::opcode_binary) {
        if (_size == 0)
            return -1;

        next_step (_tmpbuf, 1, &ws_decoder_t::flags_ready);
    } else
        return size_ready (read_from_);

    return 0;
}

int zmq::ws_decoder_t::flags_ready (unsigned char const *read_from_)
{
    unsigned char flags;

    if (_must_mask)
        flags = _tmpbuf[0] ^ _mask[0];
    else
        flags = _tmpbuf[0];

    if (flags & ws_protocol_t::more_flag)
        _msg_flags |= msg_t::more;
    if (flags & ws_protocol_t::command_flag)
        _msg_flags |= msg_t::command;

    _size--;

    return size_ready (read_from_);
}


int zmq::ws_decoder_t::size_ready (unsigned char const *read_pos_)
{
    //  Message size must not exceed the maximum allowed size.
    if (_max_msg_size >= 0)
        if (unlikely (_size > static_cast<uint64_t> (_max_msg_size))) {
            errno = EMSGSIZE;
            return -1;
        }

    //  Message size must fit into size_t data type.
    if (unlikely (_size != static_cast<size_t> (_size))) {
        errno = EMSGSIZE;
        return -1;
    }

    int rc = _in_progress.close ();
    assert (rc == 0);

    // the current message can exceed the current buffer. We have to copy the buffer
    // data into a new message and complete it in the next receive.

    shared_message_memory_allocator &allocator = get_allocator ();
    if (unlikely (!_zero_copy || allocator.data () > read_pos_
                  || static_cast<size_t> (read_pos_ - allocator.data ())
                       > allocator.size ()
                  || _size > static_cast<size_t> (
                       allocator.data () + allocator.size () - read_pos_))) {
        // a new message has started, but the size would exceed the pre-allocated arena
        // (or read_pos_ is in the initial handshake buffer)
        // this happens every time when a message does not fit completely into the buffer
        rc = _in_progress.init_size (static_cast<size_t> (_size));
    } else {
        // construct message using n bytes from the buffer as storage
        // increase buffer ref count
        // if the message will be a large message, pass a valid refcnt memory location as well
        rc = _in_progress.init (
          const_cast<unsigned char *> (read_pos_), static_cast<size_t> (_size),
          shared_message_memory_allocator::call_dec_ref, allocator.buffer (),
          allocator.provide_content ());

        // For small messages, data has been copied and refcount does not have to be increased
        if (_in_progress.is_zcmsg ()) {
            allocator.advance_content ();
            allocator.inc_ref ();
        }
    }

    if (unlikely (rc)) {
        errno_assert (errno == ENOMEM);
        rc = _in_progress.init ();
        errno_assert (rc == 0);
        errno = ENOMEM;
        return -1;
    }

    _in_progress.set_flags (_msg_flags);
    // this sets read_pos to
    // the message data address if the data needs to be copied
    // for small message / messages exceeding the current buffer
    // or
    // to the current start address in the buffer because the message
    // was constructed to use n bytes from the address passed as argument
    next_step (_in_progress.data (), _in_progress.size (),
               &ws_decoder_t::message_ready);

    return 0;
}

int zmq::ws_decoder_t::message_ready (unsigned char const *)
{
    if (_must_mask) {
        int mask_index = _opcode == ws_protocol_t::opcode_binary ? 1 : 0;

        unsigned char *data =
          static_cast<unsigned char *> (_in_progress.data ());
        for (size_t i = 0; i < _size; ++i, mask_index++)
            data[i] = data[i] ^ _mask[mask_index % 4];
    }

    //  Message is completely read. Signal this to the caller
    //  and prepare to decode next message.
    next_step (_tmpbuf, 1, &ws_decoder_t::opcode_ready);
    return 1;
}
